package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/klauspost/compress/zstd"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <path_to_deb_file> [--update-nvd] [--debug] [--test-syft]")
		os.Exit(1)
	}

	debPath := os.Args[1]
	updateNVD := len(os.Args) > 2 && (os.Args[2] == "--update-nvd" || (len(os.Args) > 3 && os.Args[3] == "--update-nvd"))
	debugMode := len(os.Args) > 2 && (os.Args[2] == "--debug" || (len(os.Args) > 3 && os.Args[3] == "--debug"))
	testSyft := len(os.Args) > 2 && (os.Args[2] == "--test-syft" || (len(os.Args) > 3 && os.Args[3] == "--test-syft"))

	// 测试模式下直接测试Syft
	if testSyft {
		testSyftDirectly(debPath)
		return
	}

	// 调试模式下输出Syft版本信息
	if debugMode {
		debugSyftVersion()
	}

	// 初始化漏洞数据库
	vulnDB := NewNVDVulnerabilityDB("./nvd_cache")

	// 如果需要，更新NVD数据库
	if updateNVD {
		err := vulnDB.UpdateDatabase()
		if err != nil {
			fmt.Printf("Warning: failed to update NVD database: %v\n", err)
		}
	}

	// 检查DEB包签名
	hasSignature, signatureInfo, err := checkDebSignature(debPath)
	if err != nil {
		fmt.Printf("Warning: failed to check DEB signature: %v\n", err)
		hasSignature = false
		signatureInfo = "Signature check failed"
	}

	// 解析deb包
	controlData, err := parseDebControlSection(debPath)
	if err != nil {
		fmt.Printf("Error parsing control section: %v\n", err)
		os.Exit(1)
	}

	// 提取包信息
	pkgInfo, err := extractPackageInfo(controlData)
	if err != nil {
		fmt.Printf("Error extracting package info: %v\n", err)
		os.Exit(1)
	}

	// 处理依赖关系
	err = processDependencies(&pkgInfo, controlData, vulnDB)
	if err != nil {
		fmt.Printf("Warning: failed to process dependencies: %v\n", err)
	}

	// 添加签名信息到根组件属性中
	if pkgInfo.Properties == nil {
		properties := []cyclonedx.Property{}
		pkgInfo.Properties = &properties
	}

	*pkgInfo.Properties = append(*pkgInfo.Properties, cyclonedx.Property{
		Name:  "has-gpg-signature",
		Value: fmt.Sprintf("%t", hasSignature),
	})

	*pkgInfo.Properties = append(*pkgInfo.Properties, cyclonedx.Property{
		Name:  "gpg-signature-info",
		Value: signatureInfo,
	})

	// 扫描deb包内容
	allComponents := []cyclonedx.Component{}
	components, err := scanDebContents(debPath, vulnDB) // 传递漏洞数据库
	if err != nil {
		fmt.Printf("Warning: Error scanning deb contents: %v\n", err)
		fmt.Println("Continuing with package-level information only...")
		// 继续处理，即使扫描内容失败，我们仍有包级别的信息
	} else {
		// 合并包信息和内容信息
		allComponents = append(allComponents, components...)
	}

	// 将包信息也添加到组件列表中
	allComponents = append([]cyclonedx.Component{pkgInfo}, allComponents...)

	// 为所有组件添加漏洞信息
	enrichedComponents := enrichComponentsWithVulnerabilities(allComponents, vulnDB)

	// 创建CycloneDX SBOM
	bom := createCycloneDXBOM(pkgInfo, enrichedComponents[1:]) // 不包括根组件本身

	// 输出到文件
	outputFile := fmt.Sprintf("%s.cdx.json", strings.TrimSuffix(filepath.Base(debPath), filepath.Ext(debPath)))
	err = writeCycloneDXBOM(bom, outputFile)
	if err != nil {
		fmt.Printf("Error writing CycloneDX SBOM: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("CycloneDX SBOM generated successfully: %s\n", outputFile)
	if len(components) > 0 {
		fmt.Printf("Found %d additional components within the package\n", len(components))
	} else {
		fmt.Println("Only package-level information was extracted (content scanning failed or produced no results)")
	}
}

// enrichComponentsWithVulnerabilities 为组件添加漏洞信息
func enrichComponentsWithVulnerabilities(components []cyclonedx.Component, vulnDB *NVDVulnerabilityDB) []cyclonedx.Component {
	enrichedComponents := make([]cyclonedx.Component, len(components))

	for i, component := range components {
		enrichedComponents[i] = component

		// 获取组件的漏洞信息
		vulnerabilities, err := vulnDB.GetVulnerabilities(component)
		if err != nil {
			fmt.Printf("Warning: failed to get vulnerabilities for component %s: %v\n", component.Name, err)
			continue
		}

		if len(vulnerabilities) > 0 {
			fmt.Printf("Found %d vulnerabilities for component %s\n", len(vulnerabilities), component.Name)

			// 为组件添加漏洞信息
			if enrichedComponents[i].Properties == nil {
				properties := []cyclonedx.Property{}
				enrichedComponents[i].Properties = &properties
			}

			// 添加漏洞统计信息
			*enrichedComponents[i].Properties = append(*enrichedComponents[i].Properties, cyclonedx.Property{
				Name:  "vulnerability-count",
				Value: fmt.Sprintf("%d", len(vulnerabilities)),
			})

			// 添加各等级漏洞数量
			criticalCount := 0
			highCount := 0
			mediumCount := 0
			lowCount := 0

			for _, vuln := range vulnerabilities {
				switch vuln.Severity {
				case "CRITICAL":
					criticalCount++
				case "HIGH":
					highCount++
				case "MEDIUM":
					mediumCount++
				case "LOW":
					lowCount++
				}
			}

			if criticalCount > 0 {
				*enrichedComponents[i].Properties = append(*enrichedComponents[i].Properties, cyclonedx.Property{
					Name:  "critical-vulnerabilities",
					Value: fmt.Sprintf("%d", criticalCount),
				})
			}

			if highCount > 0 {
				*enrichedComponents[i].Properties = append(*enrichedComponents[i].Properties, cyclonedx.Property{
					Name:  "high-vulnerabilities",
					Value: fmt.Sprintf("%d", highCount),
				})
			}

			if mediumCount > 0 {
				*enrichedComponents[i].Properties = append(*enrichedComponents[i].Properties, cyclonedx.Property{
					Name:  "medium-vulnerabilities",
					Value: fmt.Sprintf("%d", mediumCount),
				})
			}

			if lowCount > 0 {
				*enrichedComponents[i].Properties = append(*enrichedComponents[i].Properties, cyclonedx.Property{
					Name:  "low-vulnerabilities",
					Value: fmt.Sprintf("%d", lowCount),
				})
			}

			// 创建漏洞组件并添加到主组件的子组件中
			vulnComponents := make([]cyclonedx.Component, len(vulnerabilities))
			for j, vuln := range vulnerabilities {
				vulnComponents[j] = cyclonedx.Component{
					Type:        cyclonedx.ComponentTypeLibrary,
					Name:        vuln.ID,
					Version:     fmt.Sprintf("%.1f", vuln.Score),
					BOMRef:      fmt.Sprintf("cve:%s", vuln.ID),
					Description: truncateString(vuln.Description, 200), // 限制描述长度
					Properties: &[]cyclonedx.Property{
						{
							Name:  "severity",
							Value: vuln.Severity,
						},
						{
							Name:  "published",
							Value: vuln.Published,
						},
						{
							Name:  "score",
							Value: fmt.Sprintf("%.1f", vuln.Score),
						},
						{
							Name:  "component-type",
							Value: "vulnerability",
						},
					},
				}

				// 添加CPE信息（如果存在）
				if len(vuln.CPEs) > 0 {
					// 只添加前5个CPE以避免SBOM过大
					maxCPEs := len(vuln.CPEs)
					if maxCPEs > 5 {
						maxCPEs = 5
					}

					cpes := make([]cyclonedx.Property, maxCPEs)
					for k := 0; k < maxCPEs; k++ {
						cpes[k] = cyclonedx.Property{
							Name:  "cpe",
							Value: vuln.CPEs[k],
						}
					}
					*vulnComponents[j].Properties = append(*vulnComponents[j].Properties, cpes...)
				}
			}

			// 将漏洞组件添加为子组件
			enrichedComponents[i].Components = &vulnComponents
		} else {
			// 即使没有漏洞，也添加漏洞数量为0的属性
			if enrichedComponents[i].Properties == nil {
				properties := []cyclonedx.Property{}
				enrichedComponents[i].Properties = &properties
			}

			*enrichedComponents[i].Properties = append(*enrichedComponents[i].Properties, cyclonedx.Property{
				Name:  "vulnerability-count",
				Value: "0",
			})
		}
	}

	return enrichedComponents
}

// truncateString 截断字符串到指定长度
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// parseDebControlSection 解析deb包的control.tar部分
func parseDebControlSection(debPath string) (map[string]string, error) {
	f, err := os.Open(debPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// 创建临时目录来解压deb文件
	tempDir, err := os.MkdirTemp("", "deb-extract")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	// 从deb文件中提取control.tar.*
	controlFileName, err := extractControlFromDeb(f, tempDir)
	if err != nil {
		return nil, fmt.Errorf("error extracting control.tar: %v", err)
	}

	// 构建control文件路径
	controlTarPath := filepath.Join(tempDir, controlFileName)

	// 解压control文件
	controlFile, err := extractControlFile(controlTarPath)
	if err != nil {
		return nil, fmt.Errorf("error extracting control file: %v", err)
	}

	// 解析control文件
	controlData := parseControlFile(controlFile)
	return controlData, nil
}

// extractControlFromDeb 从deb文件中提取control.tar.*
func extractControlFromDeb(debFile io.Reader, outputDir string) (string, error) {
	// 读取ar文件头
	arReader := NewArReader(debFile)
	found := false
	var controlFileName string

	for {
		header, err := arReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		// 查找control.tar.*文件
		if strings.HasPrefix(header.Name, "control.tar") {
			controlFileName = header.Name
			outputPath := filepath.Join(outputDir, controlFileName)
			output, err := os.Create(outputPath)
			if err != nil {
				return "", err
			}

			_, err = io.Copy(output, arReader)
			output.Close()
			if err != nil {
				return "", err
			}
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("control.tar not found in deb file")
	}

	return controlFileName, nil
}

// extractControlFile 从control.tar.*中提取control文件内容
func extractControlFile(controlTarPath string) (string, error) {
	f, err := os.Open(controlTarPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var tarReader *tar.Reader

	// 根据文件扩展名选择解压方式
	if strings.HasSuffix(controlTarPath, ".gz") {
		gzr, err := gzip.NewReader(f)
		if err != nil {
			return "", err
		}
		defer gzr.Close()
		tarReader = tar.NewReader(gzr)
	} else if strings.HasSuffix(controlTarPath, ".xz") {
		return "", fmt.Errorf("xz compression format not yet supported for control.tar")
	} else if strings.HasSuffix(controlTarPath, ".zst") {
		zr, err := zstd.NewReader(f)
		if err != nil {
			return "", err
		}
		defer zr.Close()
		tarReader = tar.NewReader(zr)
	} else {
		// 假设未压缩的tar
		tarReader = tar.NewReader(f)
	}

	// 查找control文件
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		// 查找control文件
		if filepath.Base(header.Name) == "control" {
			content, err := io.ReadAll(tarReader)
			if err != nil {
				return "", err
			}
			return string(content), nil
		}
	}

	return "", fmt.Errorf("control file not found in control.tar")
}

// parseControlFile 解析control文件内容
func parseControlFile(content string) map[string]string {
	controlData := make(map[string]string)
	lines := strings.Split(content, "\n")

	var currentKey string
	var currentValue strings.Builder

	for _, line := range lines {
		// 跳过空行
		if line == "" {
			continue
		}

		// 检查是否是新字段（以冒号开头）
		if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// 如果之前有字段，保存它
			if currentKey != "" {
				controlData[currentKey] = strings.TrimSpace(currentValue.String())
			}

			// 分割字段名和值
			parts := strings.SplitN(line, ":", 2)
			currentKey = strings.TrimSpace(parts[0])
			currentValue.Reset()

			if len(parts) > 1 {
				currentValue.WriteString(strings.TrimSpace(parts[1]))
			}
		} else if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			// 多行值的延续行（以空格或制表符开头）
			currentValue.WriteString("\n" + strings.TrimSpace(line))
		}
	}

	// 保存最后一个字段
	if currentKey != "" {
		controlData[currentKey] = strings.TrimSpace(currentValue.String())
	}

	return controlData
}

// 修改scanDebContents函数签名以支持漏洞数据库
func scanDebContents(debPath string, vulnDB *NVDVulnerabilityDB) ([]cyclonedx.Component, error) {
	components := []cyclonedx.Component{}

	f, err := os.Open(debPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// 创建临时目录来解压deb文件
	tempDir, err := os.MkdirTemp("", "deb-extract-data")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	// 从deb文件中提取data.tar
	err = extractDataFromDeb(f, tempDir)
	if err != nil {
		return nil, fmt.Errorf("error extracting data.tar: %v", err)
	}

	// 查找实际的data文件（带扩展名）
	files, err := os.ReadDir(tempDir)
	if err != nil {
		return nil, err
	}

	var dataFilePath string
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "data.tar") {
			dataFilePath = filepath.Join(tempDir, file.Name())
			break
		}
	}

	if dataFilePath == "" {
		return nil, fmt.Errorf("data.tar not found")
	}

	fmt.Printf("Found data file: %s\n", dataFilePath)

	// 首先尝试将压缩文件解压为tar文件
	uncompressedTarPath, err := decompressDataFile(dataFilePath)
	if err != nil {
		return nil, fmt.Errorf("error decompressing data file: %v", err)
	}
	defer os.Remove(uncompressedTarPath)

	fmt.Printf("Uncompressed tar file: %s\n", uncompressedTarPath)

	// 打开解压后的tar文件
	tarFile, err := os.Open(uncompressedTarPath)
	if err != nil {
		return nil, fmt.Errorf("error opening uncompressed tar file: %v", err)
	}
	defer tarFile.Close()

	// 创建tar reader
	tarReader := tar.NewReader(tarFile)

	// 创建临时目录用于文件分析
	analysisDir, err := os.MkdirTemp("", "file-analysis")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(analysisDir)

	// 收集文件信息，而不是为每个文件创建组件
	filePaths := []string{}
	fileCount := 0
	analyzedCount := 0
	errorCount := 0

	// 先收集所有文件路径
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			errorCount++
			fmt.Printf("Warning: error reading tar header: %v\n", err)
			// 如果错误太多，停止处理
			if errorCount > 10 {
				fmt.Println("Too many errors, stopping tar processing")
				break
			}
			continue
		}

		// 只处理文件（不处理目录）
		if header.Typeflag == tar.TypeReg {
			fileCount++
			// 收集文件路径
			filePaths = append(filePaths, header.Name)

			// 对特定类型的文件进行深入分析以识别第三方组件
			// 限制分析的文件数量以避免过多的Syft调用
			if isAnalyzableFile(header.Name) && analyzedCount < 50 {
				// 提取文件名
				fileName := filepath.Base(header.Name)

				// 将文件提取到临时目录进行分析
				tempFilePath := filepath.Join(analysisDir, fileName)
				tempFile, err := os.Create(tempFilePath)
				if err != nil {
					fmt.Printf("Warning: failed to create temp file for analysis: %v\n", err)
					continue // 如果无法创建临时文件，跳过分析
				}

				// 限制文件大小以避免内存问题
				limitedReader := io.LimitReader(tarReader, 10*1024*1024) // 限制10MB
				_, err = io.Copy(tempFile, limitedReader)
				tempFile.Close()
				if err != nil {
					fmt.Printf("Warning: failed to copy file for analysis: %v\n", err)
					os.Remove(tempFilePath)
					continue
				}

				// 分析文件以识别第三方组件，并传递漏洞数据库
				identifiedComponents, err := analyzeFileForComponents(tempFilePath, vulnDB)
				if err == nil {
					components = append(components, identifiedComponents...)
					analyzedCount++
				} else {
					fmt.Printf("Warning: failed to analyze file %s: %v\n", tempFilePath, err)
				}

				// 清理临时文件
				os.Remove(tempFilePath)
			}
		}
	}

	fmt.Printf("Scanned %d files, analyzed %d files for third-party components, encountered %d errors\n", fileCount, analyzedCount, errorCount)

	// 添加一个包含所有文件路径的组件，用于表示包的整体内容
	if len(filePaths) > 0 {
		contentComponent := cyclonedx.Component{
			Type:        cyclonedx.ComponentTypeFile,
			Name:        "package-content-listing",
			Description: fmt.Sprintf("Package contains %d files", len(filePaths)),
			Properties: &[]cyclonedx.Property{
				{
					Name:  "component-type",
					Value: "content-summary",
				},
				{
					Name:  "file-count",
					Value: fmt.Sprintf("%d", len(filePaths)),
				},
			},
		}
		components = append(components, contentComponent)
	}

	return components, nil
}

// decompressDataFile 解压data.tar.*文件为tar文件
func decompressDataFile(dataFilePath string) (string, error) {
	// 创建输出文件
	outputFile, err := os.CreateTemp("", "uncompressed-*.tar")
	if err != nil {
		return "", fmt.Errorf("error creating temp file: %v", err)
	}
	defer outputFile.Close()

	inputFile, err := os.Open(dataFilePath)
	if err != nil {
		return "", fmt.Errorf("error opening input file: %v", err)
	}
	defer inputFile.Close()

	// 根据文件扩展名选择解压方式
	if strings.HasSuffix(dataFilePath, ".gz") {
		gzr, err := gzip.NewReader(inputFile)
		if err != nil {
			return "", fmt.Errorf("error creating gzip reader: %v", err)
		}
		defer gzr.Close()

		_, err = io.Copy(outputFile, gzr)
		if err != nil {
			return "", fmt.Errorf("error decompressing gzip file: %v", err)
		}
	} else if strings.HasSuffix(dataFilePath, ".xz") {
		// 对于.xz文件，尝试使用外部xz工具
		outputFile.Close()
		os.Remove(outputFile.Name())

		// 使用xz命令解压
		cmd := exec.Command("xz", "-d", "-k", "-c", dataFilePath)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return "", fmt.Errorf("error creating stdout pipe for xz: %v", err)
		}

		err = cmd.Start()
		if err != nil {
			return "", fmt.Errorf("error starting xz command: %v", err)
		}

		// 创建新的输出文件
		newOutputFile, err := os.Create(outputFile.Name())
		if err != nil {
			return "", fmt.Errorf("error creating output file: %v", err)
		}
		defer newOutputFile.Close()

		_, err = io.Copy(newOutputFile, stdout)
		if err != nil {
			return "", fmt.Errorf("error copying xz output: %v", err)
		}

		err = cmd.Wait()
		if err != nil {
			return "", fmt.Errorf("error waiting for xz command: %v", err)
		}
	} else if strings.HasSuffix(dataFilePath, ".zst") {
		zr, err := zstd.NewReader(inputFile)
		if err != nil {
			return "", fmt.Errorf("error creating zstd reader: %v", err)
		}
		defer zr.Close()

		_, err = io.Copy(outputFile, zr)
		if err != nil {
			return "", fmt.Errorf("error decompressing zstd file: %v", err)
		}
	} else {
		// 假设是普通的tar文件，直接复制
		_, err = io.Copy(outputFile, inputFile)
		if err != nil {
			return "", fmt.Errorf("error copying tar file: %v", err)
		}
	}

	return outputFile.Name(), nil
}

// isAnalyzableFile 检查文件是否需要进一步分析以识别第三方组件
func isAnalyzableFile(filename string) bool {
	// 可执行文件、共享库、jar文件等可能包含第三方组件
	analyzableExtensions := []string{
		".so", ".so.1", ".so.2", ".so.3", ".so.4", ".so.5", ".so.6", ".so.7", ".so.8", ".so.9",
		".exe", ".dll", ".dylib",
		".jar", ".war", ".ear",
		".py", ".pyc", ".pyo",
	}

	// 检查是否是可执行文件（没有扩展名但可能是可执行文件）
	if !strings.Contains(filename, ".") && (strings.HasPrefix(filename, "lib") || !strings.Contains(filename, ".")) {
		return true
	}

	for _, ext := range analyzableExtensions {
		if strings.HasSuffix(filename, ext) {
			return true
		}
	}
	return false
}
func resolveDependencies(debPath string, controlData map[string]string, visited map[string]bool) ([]cyclonedx.Component, error) {
	components := []cyclonedx.Component{}

	depends := controlData["Depends"]
	if depends == "" {
		return components, nil
	}

	dependencies := parseDependencies(depends)

	for _, dep := range dependencies {
		// 避免循环依赖
		depKey := fmt.Sprintf("%s@%s", dep.Name, dep.Version)
		if visited[depKey] {
			continue
		}
		visited[depKey] = true

		// 创建依赖组件
		depComponent := cyclonedx.Component{
			Type:       cyclonedx.ComponentTypeLibrary,
			Name:       dep.Name,
			Version:    dep.Version,
			BOMRef:     fmt.Sprintf("pkg:deb/%s@%s", dep.Name, dep.Version),
			PackageURL: fmt.Sprintf("pkg:deb/%s@%s", dep.Name, dep.Version),
			Properties: &[]cyclonedx.Property{
				{
					Name:  "component-type",
					Value: "dependency",
				},
			},
		}

		// 尝试获取依赖的详细信息（从系统已安装的包或在线仓库）
		depControlData, err := getDependencyInfo(dep.Name)
		if err == nil {
			// 如果获取到依赖信息，添加详细描述
			if description, ok := depControlData["Description"]; ok {
				depComponent.Description = description
			}

			// 递归解析依赖的依赖
			transitiveDeps, err := resolveDependencies("", depControlData, visited)
			if err == nil && len(transitiveDeps) > 0 {
				depComponent.Components = &transitiveDeps
			}
		}

		components = append(components, depComponent)
	}

	return components, nil
}

// getDependencyInfo 获取依赖包的控制信息
// 这里提供几种方式获取依赖信息：
// 1. 从系统已安装的dpkg数据库中查询
// 2. 从在线仓库查询（如果实现的话）
func getDependencyInfo(depName string) (map[string]string, error) {
	// 首先尝试从已安装的包中获取信息
	controlData, err := getInstalledPackageInfo(depName)
	if err == nil {
		return controlData, nil
	}

	// 如果本地没有安装，可以尝试从仓库获取（这里只是示例，实际需要实现仓库查询）
	// controlData, err = getRepositoryPackageInfo(depName)
	// if err == nil {
	//     return controlData, nil
	// }

	// 如果都获取不到，返回一个基本的控制信息
	return map[string]string{
		"Package": depName,
		"Version": "unknown",
	}, nil
}

// getInstalledPackageInfo 从已安装的dpkg数据库中获取包信息
func getInstalledPackageInfo(depName string) (map[string]string, error) {
	// dpkg -s 命令可以获取已安装包的信息
	cmd := exec.Command("dpkg", "-s", depName)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// 解析dpkg输出
	controlData := parseDpkgOutput(string(output))
	return controlData, nil
}

// parseDpkgOutput 解析dpkg -s命令的输出
func parseDpkgOutput(output string) map[string]string {
	controlData := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(output))

	var currentKey string
	var currentValue strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		// 空行表示段落结束
		if line == "" {
			if currentKey != "" {
				controlData[currentKey] = strings.TrimSpace(currentValue.String())
				currentKey = ""
				currentValue.Reset()
			}
			continue
		}

		// 检查是否是新字段（以冒号开头）
		if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// 保存之前的字段
			if currentKey != "" {
				controlData[currentKey] = strings.TrimSpace(currentValue.String())
			}

			// 分割字段名和值
			parts := strings.SplitN(line, ":", 2)
			currentKey = strings.TrimSpace(parts[0])
			currentValue.Reset()

			if len(parts) > 1 {
				currentValue.WriteString(strings.TrimSpace(parts[1]))
			}
		} else if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			// 多行值的延续行
			if currentKey != "" {
				currentValue.WriteString("\n" + strings.TrimSpace(line))
			}
		}
	}

	// 保存最后一个字段
	if currentKey != "" {
		controlData[currentKey] = strings.TrimSpace(currentValue.String())
	}

	return controlData
}

// extractPackageInfo 从control数据中提取包信息并创建CycloneDX组件
func extractPackageInfo(controlData map[string]string) (cyclonedx.Component, error) {
	name := controlData["Package"]
	version := controlData["Version"]
	description := controlData["Description"]
	maintainer := controlData["Maintainer"]
	architecture := controlData["Architecture"]
	homepage := controlData["Homepage"]
	license := controlData["License"] // 获取许可证信息

	// 创建CycloneDX组件
	component := cyclonedx.Component{
		Type:               cyclonedx.ComponentTypeApplication,
		Name:               name,
		Version:            version,
		Description:        description,
		BOMRef:             fmt.Sprintf("pkg:deb/%s@%s?arch=%s", name, version, architecture),
		PackageURL:         fmt.Sprintf("pkg:deb/%s@%s?arch=%s", name, version, architecture),
		Supplier:           &cyclonedx.OrganizationalEntity{Name: maintainer},
		ExternalReferences: &[]cyclonedx.ExternalReference{},
		Properties: &[]cyclonedx.Property{
			{
				Name:  "arch",
				Value: architecture,
			},
		},
	}

	// 添加许可证信息（如果存在）
	if license != "" {
		// 解析许可证信息，支持多个许可证
		licenses := parseLicenseInfo(license)
		component.Licenses = &licenses
	}

	// 添加主页引用（如果存在）
	if homepage != "" {
		*component.ExternalReferences = append(*component.ExternalReferences, cyclonedx.ExternalReference{
			URL:  homepage,
			Type: cyclonedx.ERTypeWebsite,
		})
	}

	return component, nil
}

// 修改analyzeFileForComponents函数签名以支持漏洞数据库
func analyzeFileForComponents(file_path string, vulnDB *NVDVulnerabilityDB) ([]cyclonedx.Component, error) {
	components := []cyclonedx.Component{}

	// 首先尝试使用Syft进行深度分析
	syftComponents, err := analyzeWithSyft(file_path, vulnDB) // 传递漏洞数据库
	if err == nil && len(syftComponents) > 0 {
		fmt.Printf("Syft analysis successful, found %d components in %s\n", len(syftComponents), file_path)
		components = append(components, syftComponents...)
		return components, nil
	} else if err != nil {
		fmt.Printf("Syft analysis failed for %s: %v\n", file_path, err)
	}

	// 如果Syft分析失败或不可用，则使用原有的启发式方法
	fileInfo, err := os.Stat(file_path)
	if err != nil {
		return components, err
	}

	// 根据文件名启发式识别组件（仅作示例）
	filename := filepath.Base(file_path)

	// 模拟识别一些常见的库文件
	if strings.Contains(filename, "libssl") || strings.Contains(filename, "openssl") {
		components = append(components, cyclonedx.Component{
			Type:       cyclonedx.ComponentTypeLibrary,
			Name:       "openssl",
			Version:    "unknown", // 实际应该从文件中提取版本信息
			BOMRef:     fmt.Sprintf("pkg:generic/openssl@unknown?file=%s", filename),
			PackageURL: fmt.Sprintf("pkg:generic/openssl@unknown?file=%s", filename),
		})
	}

	if strings.Contains(filename, "libcurl") {
		components = append(components, cyclonedx.Component{
			Type:       cyclonedx.ComponentTypeLibrary,
			Name:       "curl",
			Version:    "unknown",
			BOMRef:     fmt.Sprintf("pkg:generic/curl@unknown?file=%s", filename),
			PackageURL: fmt.Sprintf("pkg:generic/curl@unknown?file=%s", filename),
		})
	}

	if strings.Contains(filename, "libpng") {
		components = append(components, cyclonedx.Component{
			Type:       cyclonedx.ComponentTypeLibrary,
			Name:       "libpng",
			Version:    "unknown",
			BOMRef:     fmt.Sprintf("pkg:generic/libpng@unknown?file=%s", filename),
			PackageURL: fmt.Sprintf("pkg:generic/libpng@unknown?file=%s", filename),
		})
	}

	// 添加文件本身的组件信息
	components = append(components, cyclonedx.Component{
		Type:        cyclonedx.ComponentTypeFile,
		Name:        filename,
		Version:     "",
		BOMRef:      fmt.Sprintf("file:%s", file_path),
		Description: fmt.Sprintf("Binary file of size %d bytes", fileInfo.Size()),
	})

	return components, nil
}

// SyftResult Syft工具的JSON输出结构
type SyftResult struct {
	Artifacts []SyftArtifact `json:"artifacts"`
}

// SyftArtifact Syft识别的单个组件
type SyftArtifact struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Version   string         `json:"version"`
	Type      string         `json:"type"`
	FoundBy   string         `json:"foundBy"`
	Locations []SyftLocation `json:"locations"`
	Licenses  []string       `json:"licenses"`
	Language  string         `json:"language"`
	CPEs      []SyftCPE      `json:"cpes"`
	PURL      string         `json:"purl"`
	Metadata  SyftMetadata   `json:"metadata"`
}

// SyftLocation 组件位置信息
type SyftLocation struct {
	Path        string            `json:"path"`
	AccessPath  string            `json:"accessPath"`
	Annotations map[string]string `json:"annotations"`
}

// SyftCPE CPE信息
type SyftCPE struct {
	CPE    string `json:"cpe"`
	Source string `json:"source"`
}

// SyftMetadata 组件元数据
type SyftMetadata struct {
	Package       string   `json:"package"`
	Version       string   `json:"version"`
	Architecture  string   `json:"architecture"`
	Maintainer    string   `json:"maintainer"`
	InstalledSize int      `json:"installedSize"`
	Depends       []string `json:"depends"`
}

// debugSyftVersion 检查Syft版本
func debugSyftVersion() {
	cmd := exec.Command("syft", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to get Syft version: %v\n", err)
		return
	}
	fmt.Printf("Syft version: %s\n", string(output))
}

// debugFileAnalysis 调试图标分析
func debugFileAnalysis(filePath string) {
	fmt.Printf("Debugging file: %s\n", filePath)

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("File does not exist: %s\n", filePath)
		return
	}

	// 检查文件大小
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		fmt.Printf("Failed to stat file: %v\n", err)
		return
	}

	fmt.Printf("File size: %d bytes\n", fileInfo.Size())

	// 检查文件类型
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	// 读取文件头部信息
	header := make([]byte, 16)
	_, err = file.Read(header)
	if err != nil {
		fmt.Printf("Failed to read file header: %v\n", err)
		return
	}

	fmt.Printf("File header (hex): %x\n", header)
}

// analyzeWithSyft 使用Syft分析文件中的第三方组件
func analyzeWithSyft(filePath string, vulnDB *NVDVulnerabilityDB) ([]cyclonedx.Component, error) {
	components := []cyclonedx.Component{}

	// 检查Syft是否可用
	_, err := exec.LookPath("syft")
	if err != nil {
		fmt.Printf("Warning: syft not found in PATH: %v\n", err)
		return components, fmt.Errorf("syft not found in PATH: %v", err)
	}

	fmt.Printf("Analyzing file with Syft: %s\n", filePath)

	// 检查文件是否存在且可读
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return components, fmt.Errorf("file does not exist: %s", filePath)
	}

	// 首先尝试不同的Syft命令格式
	cmdFormats := [][]string{
		{"syft", filePath, "-o", "json"},
		{"syft", filePath, "--output", "json"},
		{"syft", "scan", filePath, "-o", "json"},
	}

	var stdout, stderr bytes.Buffer
	var cmd *exec.Cmd
	success := false

	for i, format := range cmdFormats {
		fmt.Printf("Trying Syft command format %d: %v\n", i+1, format)
		cmd = exec.Command(format[0], format[1:]...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err = cmd.Run()
		if err == nil {
			fmt.Printf("Syft command format %d succeeded\n", i+1)
			success = true
			break
		} else {
			fmt.Printf("Syft command format %d failed: %v\n", i+1, err)
			fmt.Printf("Stderr: %s\n", stderr.String())
			stdout.Reset()
			stderr.Reset()
		}
	}

	if !success {
		return components, fmt.Errorf("all Syft command formats failed")
	}

	output := stdout.Bytes()
	fmt.Printf("Syft output length: %d bytes\n", len(output))

	// 检查输出是否为空
	if len(output) == 0 {
		return components, fmt.Errorf("syft returned empty output")
	}

	// 尝试解析输出
	var syftResult SyftResult
	err = json.Unmarshal(output, &syftResult)
	if err != nil {
		fmt.Printf("Warning: failed to parse syft output: %v\n", err)
		// 打印部分输出内容用于调试
		if len(output) > 500 {
			fmt.Printf("Syft output (first 500 chars): %s...\n", string(output[:500]))
		} else {
			fmt.Printf("Syft output: %s\n", string(output))
		}
		// 尝试保存原始输出到文件以便调试
		debugFile := filepath.Join(os.TempDir(), "syft-debug-output.json")
		err := os.WriteFile(debugFile, output, 0644)
		if err == nil {
			fmt.Printf("Full Syft output saved to: %s\n", debugFile)
		}
		return components, fmt.Errorf("failed to parse syft output: %v", err)
	}

	fmt.Printf("Syft found %d artifacts\n", len(syftResult.Artifacts))

	// 转换Syft结果为CycloneDX组件
	for _, artifact := range syftResult.Artifacts {
		component := cyclonedx.Component{
			Type:    cyclonedx.ComponentTypeLibrary,
			Name:    artifact.Name,
			Version: artifact.Version,
			BOMRef:  artifact.ID,
		}

		// 设置PackageURL（如果存在）
		if artifact.PURL != "" {
			component.PackageURL = artifact.PURL
		}

		// 设置描述信息
		if artifact.Metadata.Maintainer != "" {
			component.Description = fmt.Sprintf("Maintainer: %s", artifact.Metadata.Maintainer)
		}

		// 设置CPE（如果存在）
		if len(artifact.CPEs) > 0 {
			// CPE通常不直接在CycloneDX组件中设置，但可以作为属性添加
			if component.Properties == nil {
				properties := []cyclonedx.Property{}
				component.Properties = &properties
			}

			for _, cpe := range artifact.CPEs {
				*component.Properties = append(*component.Properties, cyclonedx.Property{
					Name:  "cpe",
					Value: cpe.CPE,
				})
			}
		}

		// 设置许可证信息
		if len(artifact.Licenses) > 0 {
			// 创建许可证集合
			licenses := cyclonedx.Licenses{}
			for _, license := range artifact.Licenses {
				licenses = append(licenses, cyclonedx.LicenseChoice{
					License: &cyclonedx.License{
						Name: license,
					},
				})
			}
			component.Licenses = &licenses
		}

		// 添加架构属性
		if artifact.Metadata.Architecture != "" {
			if component.Properties == nil {
				properties := []cyclonedx.Property{}
				component.Properties = &properties
			}
			*component.Properties = append(*component.Properties, cyclonedx.Property{
				Name:  "architecture",
				Value: artifact.Metadata.Architecture,
			})
		}

		// 添加类型属性
		if component.Properties == nil {
			properties := []cyclonedx.Property{}
			component.Properties = &properties
		}
		*component.Properties = append(*component.Properties, cyclonedx.Property{
			Name:  "syft-type",
			Value: artifact.Type,
		})

		// 添加发现方式属性
		*component.Properties = append(*component.Properties, cyclonedx.Property{
			Name:  "found-by",
			Value: artifact.FoundBy,
		})

		components = append(components, component)
	}

	fmt.Printf("Converted %d components from Syft output\n", len(components))
	return components, nil
}

// testSyftDirectly 直接测试Syft是否能分析文件
func testSyftDirectly(filePath string) {
	fmt.Printf("Testing Syft directly on file: %s\n", filePath)

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("File does not exist: %s\n", filePath)
		return
	}

	// 获取文件信息
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		fmt.Printf("Error getting file info: %v\n", err)
		return
	}

	fmt.Printf("File size: %d bytes\n", fileInfo.Size())

	// 尝试几种不同的Syft命令
	cmds := [][]string{
		{"syft", filePath, "-o", "json"},
		{"syft", "--output", "json", filePath},
		{"syft", "scan", filePath, "-o", "json"},
	}

	for i, cmdArgs := range cmds {
		fmt.Printf("\nTrying command %d: %v\n", i+1, strings.Join(cmdArgs, " "))

		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			fmt.Printf("Command failed with error: %v\n", err)
			fmt.Printf("Stderr: %s\n", stderr.String())
			continue
		}

		output := stdout.Bytes()
		fmt.Printf("Command succeeded, output size: %d bytes\n", len(output))

		if len(output) > 0 {
			// 尝试解析JSON
			var result map[string]interface{}
			if err := json.Unmarshal(output, &result); err != nil {
				fmt.Printf("Failed to parse JSON: %v\n", err)
				// 显示前500个字符
				if len(output) > 500 {
					fmt.Printf("Output preview: %s...\n", string(output[:500]))
				} else {
					fmt.Printf("Output: %s\n", string(output))
				}
			} else {
				// 成功解析JSON
				if artifacts, ok := result["artifacts"]; ok {
					if artifactList, ok := artifacts.([]interface{}); ok {
						fmt.Printf("Found %d artifacts\n", len(artifactList))
						// 显示前几个artifacts的名称
						for j, artifact := range artifactList {
							if j >= 3 { // 只显示前3个
								break
							}
							if artifactMap, ok := artifact.(map[string]interface{}); ok {
								if name, ok := artifactMap["name"]; ok {
									fmt.Printf("  Artifact %d: %s\n", j+1, name)
								}
							}
						}
					}
				}

				// 保存完整输出到临时文件
				tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("syft-test-output-%d.json", i+1))
				if err := os.WriteFile(tempFile, output, 0644); err == nil {
					fmt.Printf("Full output saved to: %s\n", tempFile)
				}
			}
		}
		return // 如果任何一个命令成功，就退出
	}

	fmt.Printf("All Syft commands failed\n")
}

// Dependency 依赖信息结构
type Dependency struct {
	Name    string
	Version string
}

// parseDependencies 解析依赖字符串
func parseDependencies(depends string) []Dependency {
	var dependencies []Dependency

	// 依赖项之间用逗号分隔
	depList := strings.Split(depends, ",")

	for _, dep := range depList {
		dep = strings.TrimSpace(dep)

		// 查找版本约束符号
		var name, version string
		if strings.Contains(dep, ">=") {
			parts := strings.Split(dep, ">=")
			name = strings.TrimSpace(parts[0])
			version = ">=" + strings.TrimSpace(parts[1])
		} else if strings.Contains(dep, "<=") {
			parts := strings.Split(dep, "<=")
			name = strings.TrimSpace(parts[0])
			version = "<=" + strings.TrimSpace(parts[1])
		} else if strings.Contains(dep, "=") {
			parts := strings.Split(dep, "=")
			name = strings.TrimSpace(parts[0])
			version = "=" + strings.TrimSpace(parts[1])
		} else if strings.Contains(dep, "<<") {
			parts := strings.Split(dep, "<<")
			name = strings.TrimSpace(parts[0])
			version = "<<" + strings.TrimSpace(parts[1])
		} else if strings.Contains(dep, ">>") {
			parts := strings.Split(dep, ">>")
			name = strings.TrimSpace(parts[0])
			version = ">>" + strings.TrimSpace(parts[1])
		} else {
			// 没有版本约束
			name = dep
			version = "any"
		}

		dependencies = append(dependencies, Dependency{
			Name:    name,
			Version: version,
		})
	}

	return dependencies
}

// parseLicenseInfo 解析许可证信息并转换为CycloneDX格式
func parseLicenseInfo(licenseStr string) cyclonedx.Licenses {
	licenses := cyclonedx.Licenses{}

	// 处理多个许可证的情况，它们可能由逗号、空格或"or"/"and"分隔
	// 先按逗号分割
	parts := strings.Split(licenseStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		// 进一步处理"or"和"and"分隔的情况
		subParts := splitLicenseExpression(part)

		for _, subPart := range subParts {
			subPart = strings.TrimSpace(subPart)
			if subPart == "" {
				continue
			}

			// 检查是否是SPDX许可证ID
			if isValidSPDXLicense(subPart) {
				licenses = append(licenses, cyclonedx.LicenseChoice{
					License: &cyclonedx.License{
						ID: subPart,
					},
				})
			} else {
				// 如果不是标准SPDX ID，则作为名称处理
				licenses = append(licenses, cyclonedx.LicenseChoice{
					License: &cyclonedx.License{
						Name: subPart,
					},
				})
			}
		}
	}

	// 如果没有找到任何许可证，添加一个未知许可证
	if len(licenses) == 0 {
		licenses = append(licenses, cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				Name: "UNKNOWN",
			},
		})
	}

	return licenses
}

// splitLicenseExpression 拆分许可证表达式
func splitLicenseExpression(expr string) []string {
	// 处理常见的分隔符
	expr = strings.ReplaceAll(expr, " or ", ",")
	expr = strings.ReplaceAll(expr, " OR ", ",")
	expr = strings.ReplaceAll(expr, " and ", ",")
	expr = strings.ReplaceAll(expr, " AND ", ",")
	expr = strings.ReplaceAll(expr, " ", ",")

	return strings.Split(expr, ",")
}

// isValidSPDXLicense 检查许可证名称是否为有效的SPDX许可证标识符
func isValidSPDXLicense(license string) bool {
	// 常见的SPDX许可证标识符列表（部分）
	validSPDXLicenses := map[string]bool{
		"Apache-2.0":       true,
		"MIT":              true,
		"GPL-2.0":          true,
		"GPL-3.0":          true,
		"BSD-2-Clause":     true,
		"BSD-3-Clause":     true,
		"ISC":              true,
		"MPL-2.0":          true,
		"Unlicense":        true,
		"CC0-1.0":          true,
		"CC-BY-4.0":        true,
		"CC-BY-SA-4.0":     true,
		"LGPL-2.1":         true,
		"LGPL-3.0":         true,
		"EPL-2.0":          true,
		"AGPL-3.0":         true,
		"BSL-1.0":          true,
		"MS-PL":            true,
		"MS-RL":            true,
		"Zlib":             true,
		"OSL-3.0":          true,
		"PostgreSQL":       true,
		"OFL-1.1":          true,
		"NCSA":             true,
		"Unicode-DFS-2016": true,
		"UPL-1.0":          true,
		"Python-2.0":       true,
		"PHP-3.01":         true,
		"OpenSSL":          true,
		"OGC-1.0":          true,
		"NASA-1.3":         true,
		"Libpng":           true,
		"Latex2e":          true,
		"IJG":              true,
		"ImageMagick":      true,
		"HPND":             true,
		"FSFAP":            true,
		"FSFUL":            true,
		"FSFULLR":          true,
		"EUPL-1.1":         true,
		"EUPL-1.2":         true,
		"ECL-2.0":          true,
		"DOC":              true,
		"CDDL-1.0":         true,
		"CDDL-1.1":         true,
		"CATOSL-1.1":       true,
		"BitTorrent-1.1":   true,
		"blessing":         true,
		"AFL-3.0":          true,
		"Adobe-Glyph":      true,
		"Adobe-2006":       true,
		"0BSD":             true,
	}

	// 简单检查是否包含典型的SPDX表达式语法
	hasExpressionSyntax := strings.Contains(license, " OR ") ||
		strings.Contains(license, " AND ") ||
		strings.Contains(license, "(") ||
		strings.Contains(license, "+")

	// 如果在有效列表中或者包含表达式语法，则认为是有效的SPDX许可证
	return validSPDXLicenses[license] || hasExpressionSyntax
}

// ... existing code ...

// extractDataFromDeb 从deb文件中提取data.tar
func extractDataFromDeb(debFile io.Reader, outputDir string) error {
	// 由于我们需要多次读取debFile，我们先将其内容读入内存
	debContent, err := io.ReadAll(debFile)
	if err != nil {
		return fmt.Errorf("error reading deb file: %v", err)
	}

	// 创建ar reader
	arReader := NewArReader(bytes.NewReader(debContent))
	found := false
	for {
		header, err := arReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading ar header: %v", err)
		}

		// 查找data.tar文件
		if strings.HasPrefix(header.Name, "data.tar") {
			outputPath := filepath.Join(outputDir, header.Name)
			output, err := os.Create(outputPath)
			if err != nil {
				return fmt.Errorf("error creating output file %s: %v", outputPath, err)
			}

			// 限制读取大小以避免潜在的内存问题
			limitedReader := io.LimitReader(arReader, header.Size)
			_, err = io.Copy(output, limitedReader)
			output.Close()
			if err != nil {
				return fmt.Errorf("error writing to output file %s: %v", outputPath, err)
			}
			found = true
			fmt.Printf("Successfully extracted %s (%d bytes)\n", header.Name, header.Size)
			break
		}
	}

	if !found {
		return fmt.Errorf("data.tar not found in deb file")
	}

	return nil
}

// getFileExtension 获取文件扩展名
func getFileExtension(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) > 1 {
		return strings.Join(parts[1:], ".")
	}
	return ""
}

func createCycloneDXBOM(rootComponent cyclonedx.Component, components []cyclonedx.Component) *cyclonedx.BOM {
	bom := &cyclonedx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cyclonedx.SpecVersion1_5,
		Version:      1,
		SerialNumber: fmt.Sprintf("urn:uuid:%s", generateUUID()),
		Metadata: &cyclonedx.Metadata{
			Timestamp: time.Now().Format(time.RFC3339),
			Tools: &cyclonedx.ToolsChoice{
				Tools: &[]cyclonedx.Tool{
					{
						Name:    "deb-sbom-generator",
						Version: "1.0.0",
						Vendor:  "Open Source Community",
					},
				},
			},
			Component: &rootComponent,
		},
		Components: &components,
	}

	return bom
}

// generateUUID 生成UUID字符串
func generateUUID() string {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		// 如果无法生成随机UUID，则使用时间戳生成伪UUID
		timestamp := time.Now().UnixNano()
		return fmt.Sprintf("xxxxxxxx-xxxx-4xxx-yxxx-%012x", timestamp&0xFFFFFFFFFFFF)
	}

	// 设置版本号为4 (随机UUID)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// 设置变体位
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}

// writeCycloneDXBOM 将BOM写入JSON文件
func writeCycloneDXBOM(bom *cyclonedx.BOM, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := cyclonedx.NewBOMEncoder(file, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.Encode(bom)
}

// ArReader 用于读取ar归档文件
type ArReader struct {
	reader      io.Reader
	headerRead  bool
	currentSize int64
	currentRead int64
}

// ArHeader ar文件头
type ArHeader struct {
	Name string
	Size int64
}

// NewArReader 创建新的ArReader
func NewArReader(r io.Reader) *ArReader {
	return &ArReader{reader: r, headerRead: false}
}

// Next 移动到下一个文件
func (ar *ArReader) Next() (*ArHeader, error) {
	// 如果当前文件还没有读取完，先跳过剩余部分
	if ar.currentRead < ar.currentSize {
		remaining := ar.currentSize - ar.currentRead
		_, err := io.CopyN(io.Discard, ar.reader, remaining)
		if err != nil {
			return nil, err
		}

		// 如果大小是奇数，跳过对齐字节
		if ar.currentSize%2 == 1 {
			_, err = io.CopyN(io.Discard, ar.reader, 1)
			if err != nil && err != io.EOF {
				return nil, err
			}
		}
	}

	// 读取ar文件全局头（仅在第一次调用时）
	if !ar.headerRead {
		header := make([]byte, 8)
		_, err := io.ReadFull(ar.reader, header)
		if err != nil {
			return nil, err
		}

		// 检查ar文件魔数
		if string(header) != "!<arch>\n" {
			return nil, fmt.Errorf("not an ar archive")
		}
		ar.headerRead = true
	}

	// 读取文件头 (60 bytes)
	fileHeader := make([]byte, 60)
	n, err := io.ReadFull(ar.reader, fileHeader)
	if err == io.EOF || n == 0 {
		return nil, io.EOF
	}
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	if n < 60 {
		return nil, io.EOF
	}

	// 解析文件名
	name := strings.TrimRight(string(fileHeader[:16]), " ")
	// 处理GNU风格的文件名
	if name == "/" {
		// 这是符号表，跳过
		return ar.Next()
	} else if name == "//" {
		// 这是长文件名表，跳过
		return ar.Next()
	}

	// 解析文件大小
	sizeStr := strings.TrimRight(string(fileHeader[48:58]), " ")
	size, err := parseDecimal(sizeStr)
	if err != nil {
		return nil, err
	}

	// 重置读取计数器
	ar.currentSize = size
	ar.currentRead = 0

	return &ArHeader{
		Name: name,
		Size: size,
	}, nil
}

// parseDecimal 解析十进制数字字符串
func parseDecimal(s string) (int64, error) {
	var result int64
	for _, r := range s {
		if r >= '0' && r <= '9' {
			result = result*10 + int64(r-'0')
		} else {
			break
		}
	}
	return result, nil
}

// Read 实现io.Reader接口
func (ar *ArReader) Read(p []byte) (n int, err error) {
	if ar.currentRead >= ar.currentSize {
		return 0, io.EOF
	}

	remaining := ar.currentSize - ar.currentRead
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	n, err = ar.reader.Read(p)
	ar.currentRead += int64(n)

	// 如果读取完了并且大小是奇数，消耗对齐字节
	if ar.currentRead >= ar.currentSize && ar.currentSize%2 == 1 {
		ar.reader.Read(make([]byte, 1))
	}

	return n, err
}

// CveInfo CVE信息结构
type CveInfo struct {
	ID          string   `json:"cve_id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	CPEs        []string `json:"cpes"`
	Published   string   `json:"published"`
}

// VulnerabilityDatabase 漏洞数据库接口
type VulnerabilityDatabase interface {
	GetVulnerabilities(component cyclonedx.Component) ([]CveInfo, error)
	UpdateDatabase() error
}

// NVDVulnerabilityDB NVD漏洞数据库实现
type NVDVulnerabilityDB struct {
	dbPath string
	cache  map[string][]CveInfo
}

// NewNVDVulnerabilityDB 创建NVD漏洞数据库实例
func NewNVDVulnerabilityDB(dbPath string) *NVDVulnerabilityDB {
	return &NVDVulnerabilityDB{
		dbPath: dbPath,
		cache:  make(map[string][]CveInfo),
	}
}

// UpdateDatabase 更新NVD数据库
func (nvd *NVDVulnerabilityDB) UpdateDatabase() error {
	fmt.Println("Updating NVD database...")

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "nvd-download")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 下载最新的NVD数据（最近几年的数据）
	years := []int{2023, 2024, 2025} // 可以根据需要调整年份
	for _, year := range years {
		url := fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz", year)
		gzFilePath := filepath.Join(tempDir, fmt.Sprintf("nvdcve-1.1-%d.json.gz", year))
		jsonFilePath := filepath.Join(tempDir, fmt.Sprintf("nvdcve-1.1-%d.json", year))

		// 下载.gz文件
		err := nvd.downloadFile(url, gzFilePath)
		if err != nil {
			fmt.Printf("Warning: failed to download NVD data for %d: %v\n", year, err)
			continue
		}

		// 解压文件
		err = nvd.extractGzFile(gzFilePath, jsonFilePath)
		if err != nil {
			fmt.Printf("Warning: failed to extract NVD data for %d: %v\n", year, err)
			continue
		}

		// 处理JSON数据
		err = nvd.processNVDJson(jsonFilePath)
		if err != nil {
			fmt.Printf("Warning: failed to process NVD data for %d: %v\n", year, err)
			continue
		}
	}

	fmt.Println("NVD database updated successfully")
	return nil
}

// downloadFile 下载文件
func (nvd *NVDVulnerabilityDB) downloadFile(url, filepath string) error {
	// 检查文件是否已存在且较新
	if info, err := os.Stat(filepath); err == nil {
		// 如果文件在24小时内下载过，跳过
		if time.Since(info.ModTime()) < 24*time.Hour {
			return nil
		}
	}

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// extractGzFile 解压gz文件
func (nvd *NVDVulnerabilityDB) extractGzFile(gzFilePath, outputFilePath string) error {
	gzFile, err := os.Open(gzFilePath)
	if err != nil {
		return err
	}
	defer gzFile.Close()

	gzReader, err := gzip.NewReader(gzFile)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, gzReader)
	return err
}

// NVD JSON结构定义
type NVDResponse struct {
	CVEItems []CVEItem `json:"CVE_Items"`
}

type CVEItem struct {
	Cve           CVEData `json:"cve"`
	Impact        Impact  `json:"impact"`
	PublishedDate string  `json:"publishedDate"`
}

type CVEData struct {
	CVEDataMeta    CVEDataMeta    `json:"CVE_data_meta"`
	Description    Description    `json:"description"`
	References     References     `json:"references"`
	Configurations Configurations `json:"configurations"`
}

type CVEDataMeta struct {
	ID string `json:"ID"`
}

type Description struct {
	DescriptionData []DescriptionData `json:"description_data"`
}

type DescriptionData struct {
	Value string `json:"value"`
}

type Configurations struct {
	Nodes []Node `json:"nodes"`
}

type Node struct {
	CPEMatch []CPEMatch `json:"cpe_match"`
}

type CPEMatch struct {
	CPE23URI   string `json:"cpe23Uri"`
	Vulnerable bool   `json:"vulnerable"`
}

type References struct {
	ReferenceData []ReferenceData `json:"reference_data"`
}

type ReferenceData struct {
	URL string `json:"url"`
}

// 补充完整的NVD数据结构
type Impact struct {
	BaseMetricV2 *BaseMetricV2 `json:"baseMetricV2,omitempty"`
	BaseMetricV3 *BaseMetricV3 `json:"baseMetricV3,omitempty"`
}

type BaseMetricV2 struct {
	CVSSV2   CVSSV2 `json:"cvssV2"`
	Severity string `json:"severity"`
}

type BaseMetricV3 struct {
	CVSSV3 CVSSV3 `json:"cvssV3"`
}

type CVSSV2 struct {
	BaseScore float64 `json:"baseScore"`
}

type CVSSV3 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// processNVDJson 处理NVD JSON文件
func (nvd *NVDVulnerabilityDB) processNVDJson(jsonFilePath string) error {
	fmt.Printf("Processing NVD data from %s\n", jsonFilePath)

	file, err := os.Open(jsonFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var response NVDResponse
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&response)
	if err != nil {
		return err
	}

	fmt.Printf("Processing %d CVE items\n", len(response.CVEItems))

	// 处理每个CVE项目
	for _, item := range response.CVEItems {
		cveInfo := CveInfo{
			ID:        item.Cve.CVEDataMeta.ID,
			Published: item.PublishedDate,
		}

		// 获取描述
		if len(item.Cve.Description.DescriptionData) > 0 {
			cveInfo.Description = item.Cve.Description.DescriptionData[0].Value
		}

		// 获取评分
		if item.Impact.BaseMetricV3 != nil {
			cveInfo.Score = item.Impact.BaseMetricV3.CVSSV3.BaseScore
			cveInfo.Severity = item.Impact.BaseMetricV3.CVSSV3.BaseSeverity
		} else if item.Impact.BaseMetricV2 != nil {
			cveInfo.Score = item.Impact.BaseMetricV2.CVSSV2.BaseScore
			cveInfo.Severity = nvd.getSeverityFromScore(cveInfo.Score)
		}

		// 获取相关的CPE信息
		for _, node := range item.Cve.Configurations.Nodes {
			for _, cpeMatch := range node.CPEMatch {
				if cpeMatch.Vulnerable {
					cveInfo.CPEs = append(cveInfo.CPEs, cpeMatch.CPE23URI)
				}
			}
		}

		// 将CVE信息存储到缓存中（按CPE索引）
		for _, cpe := range cveInfo.CPEs {
			if nvd.cache[cpe] == nil {
				nvd.cache[cpe] = []CveInfo{}
			}
			nvd.cache[cpe] = append(nvd.cache[cpe], cveInfo)
		}
	}

	fmt.Printf("Processed NVD data, cache size: %d CPE entries\n", len(nvd.cache))
	return nil
}

// getSeverityFromScore 根据评分获取严重性等级
func (nvd *NVDVulnerabilityDB) getSeverityFromScore(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	} else if score > 0.0 {
		return "LOW"
	}
	return "NONE"
}

// GetVulnerabilities 获取组件的漏洞信息
func (nvd *NVDVulnerabilityDB) GetVulnerabilities(component cyclonedx.Component) ([]CveInfo, error) {
	var vulnerabilities []CveInfo

	// 方法1: 通过CPE匹配
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if prop.Name == "cpe" {
				if cveList, exists := nvd.cache[prop.Value]; exists {
					vulnerabilities = append(vulnerabilities, cveList...)
				}
			}
		}
	}

	// 方法2: 通过PackageURL匹配
	if component.PackageURL != "" {
		// 尝试从PURL生成CPE并匹配
		cpe := nvd.purlToCPE(component.PackageURL)
		if cveList, exists := nvd.cache[cpe]; exists {
			vulnerabilities = append(vulnerabilities, cveList...)
		}
	}

	// 方法3: 通过名称和版本匹配
	// 这需要更复杂的匹配逻辑，可以根据需要实现

	// 去重
	uniqueVulns := nvd.deduplicateVulnerabilities(vulnerabilities)
	return uniqueVulns, nil
}

// purlToCPE 将PackageURL转换为CPE格式（简化版本）
func (nvd *NVDVulnerabilityDB) purlToCPE(purl string) string {
	// 这是一个简化的转换，实际应用中需要更复杂的逻辑
	// 例如: pkg:deb/openssl@1.1.1 -> cpe:2.3:a:openssl:openssl:1.1.1
	if strings.HasPrefix(purl, "pkg:deb/") {
		parts := strings.Split(purl, "/")
		if len(parts) >= 3 {
			pkgInfo := strings.Split(parts[2], "@")
			if len(pkgInfo) >= 1 {
				pkgName := pkgInfo[0]
				version := ""
				if len(pkgInfo) >= 2 {
					version = pkgInfo[1]
				}
				// 简化处理，实际需要更精确的转换
				return fmt.Sprintf("cpe:2.3:a:%s:%s:%s", pkgName, pkgName, version)
			}
		}
	}
	return ""
}

// deduplicateVulnerabilities 去除重复的漏洞信息
func (nvd *NVDVulnerabilityDB) deduplicateVulnerabilities(vulns []CveInfo) []CveInfo {
	seen := make(map[string]bool)
	result := []CveInfo{}

	for _, vuln := range vulns {
		if !seen[vuln.ID] {
			seen[vuln.ID] = true
			result = append(result, vuln)
		}
	}

	return result
}

// processDependencies 处理依赖关系并创建依赖组件
func processDependencies(rootComponent *cyclonedx.Component, controlData map[string]string, vulnDB *NVDVulnerabilityDB) error {
	depends := controlData["Depends"]
	if depends == "" {
		return nil
	}

	// 解析依赖项
	dependencies := parseDependencies(depends)
	componentList := make([]cyclonedx.Component, 0, len(dependencies))

	for _, dep := range dependencies {
		// 获取依赖包信息
		depInfo, err := getDependencyInfo(dep.Name)
		if err != nil {
			// 如果无法获取依赖信息，创建一个基本的依赖组件
			depComponent := cyclonedx.Component{
				Type:       cyclonedx.ComponentTypeLibrary,
				Name:       dep.Name,
				Version:    dep.Version,
				BOMRef:     fmt.Sprintf("pkg:deb/%s@%s", dep.Name, dep.Version),
				PackageURL: fmt.Sprintf("pkg:deb/%s@%s", dep.Name, dep.Version),
				Properties: &[]cyclonedx.Property{
					{
						Name:  "component-type",
						Value: "dependency",
					},
				},
			}
			componentList = append(componentList, depComponent)
			continue
		}

		// 创建依赖组件
		depComponent := cyclonedx.Component{
			Type:        cyclonedx.ComponentTypeLibrary,
			Name:        depInfo["Package"],
			Version:     depInfo["Version"],
			Description: depInfo["Description"],
			BOMRef:      fmt.Sprintf("pkg:deb/%s@%s", depInfo["Package"], depInfo["Version"]),
			PackageURL:  fmt.Sprintf("pkg:deb/%s@%s", depInfo["Package"], depInfo["Version"]),
			Supplier:    &cyclonedx.OrganizationalEntity{Name: depInfo["Maintainer"]},
			Properties: &[]cyclonedx.Property{
				{
					Name:  "component-type",
					Value: "dependency",
				},
				{
					Name:  "arch",
					Value: depInfo["Architecture"],
				},
			},
		}

		// 添加主页引用（如果存在）
		if depInfo["Homepage"] != "" {
			depComponent.ExternalReferences = &[]cyclonedx.ExternalReference{
				{
					URL:  depInfo["Homepage"],
					Type: cyclonedx.ERTypeWebsite,
				},
			}
		}

		componentList = append(componentList, depComponent)
	}

	// 将依赖组件设置为根组件的子组件
	rootComponent.Components = &componentList
	return nil
}

// checkDebSignature 检查DEB包是否包含GPG签名
func checkDebSignature(debPath string) (hasSignature bool, signatureInfo string, err error) {
	f, err := os.Open(debPath)
	if err != nil {
		return false, "", err
	}
	defer f.Close()

	// 创建ar reader来读取DEB文件
	arReader := NewArReader(f)

	signatureFiles := []string{}

	for {
		header, err := arReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, "", fmt.Errorf("error reading ar header: %v", err)
		}

		// 检查是否有签名相关的文件
		if strings.HasPrefix(header.Name, "_gpg") ||
			strings.HasPrefix(header.Name, "sign") ||
			strings.HasSuffix(header.Name, ".asc") ||
			strings.HasSuffix(header.Name, ".sig") ||
			header.Name == "signature" {
			signatureFiles = append(signatureFiles, header.Name)
		}
	}

	if len(signatureFiles) > 0 {
		hasSignature = true
		signatureInfo = fmt.Sprintf("Signed with files: %s", strings.Join(signatureFiles, ", "))
	} else {
		// 尝试使用外部工具验证签名
		cmd := exec.Command("dpkg-sig", "--verify", debPath)
		output, err := cmd.CombinedOutput()
		if err == nil {
			hasSignature = true
			signatureInfo = fmt.Sprintf("Verified with dpkg-sig: %s", strings.TrimSpace(string(output)))
		} else {
			// 再尝试使用ar命令检查是否有签名文件
			cmd = exec.Command("ar", "-t", debPath)
			output, err := cmd.Output()
			if err == nil {
				lines := strings.Split(strings.TrimSpace(string(output)), "\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "_gpg") ||
						strings.HasPrefix(line, "sign") ||
						strings.HasSuffix(line, ".asc") ||
						strings.HasSuffix(line, ".sig") ||
						line == "signature" {
						signatureFiles = append(signatureFiles, line)
					}
				}

				if len(signatureFiles) > 0 {
					hasSignature = true
					signatureInfo = fmt.Sprintf("Signed with files: %s", strings.Join(signatureFiles, ", "))
				} else {
					signatureInfo = "No signature found"
				}
			} else {
				signatureInfo = "Unable to check signature"
			}
		}
	}

	return hasSignature, signatureInfo, nil
}
