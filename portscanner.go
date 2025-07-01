package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// Embedded XSLT for masscan output
const masscanXSLT = `<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:key name="by-ip" match="host" use="address/@addr"/>
  <xsl:template match="/">
    <xsl:for-each select="//host[generate-id() = generate-id(key('by-ip', address/@addr)[1])]">
      <xsl:variable name="ip" select="address/@addr"/>
      <xsl:variable name="ports" select="key('by-ip', $ip)/ports/port[state/@state='open']/@portid"/>
      <xsl:if test="$ports">
        <xsl:value-of select="$ip"/>
        <xsl:text>:</xsl:text>
        <xsl:for-each select="$ports">
          <xsl:value-of select="."/>
          <xsl:if test="position() != last()">
            <xsl:text>,</xsl:text>
          </xsl:if>
        </xsl:for-each>
        <xsl:text>
</xsl:text>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>`

// Embedded XSLT for Nmap output
const nmapXSLT = `<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:for-each select="//host">
      <xsl:variable name="ip" select="address/@addr"/>
      <xsl:for-each select="ports/port[state/@state='open']">
        <xsl:text>[</xsl:text>
        <xsl:value-of select="$ip"/>
        <xsl:text>:</xsl:text>
        <xsl:value-of select="@portid"/>
        <xsl:text>] [</xsl:text>
        <xsl:value-of select="service/@name"/>
        <xsl:text>] [</xsl:text>
        <xsl:value-of select="normalize-space(concat(service/@product, ' ', service/@version, ' ', service/@extrainfo))"/>
        <xsl:text>]</xsl:text>
        <xsl:text>
</xsl:text>
      </xsl:for-each>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>`

func main() {
	// Parse command-line flags
	inputFile := flag.String("i", "", "Input file containing list of IPs (one per line)")
	outputFile := flag.String("o", "", "Output file for scan results")
	flag.Parse()

	// Validate flags
	if *inputFile == "" || *outputFile == "" {
		fmt.Println("Error: Both -i (input file) and -o (output file) are required")
		fmt.Println("Usage: portscanner -i <input_file> -o <output_file>")
		os.Exit(1)
	}

	// Check if input file exists
	if _, err := os.Stat(*inputFile); os.IsNotExist(err) {
		fmt.Printf("Error: Input file %s not found\n", *inputFile)
		os.Exit(1)
	}

	// Create temporary files for masscan and nmap output
	masscanOut, err := ioutil.TempFile("", "masscan_output_*.xml")
	if err != nil {
		fmt.Printf("Error: Failed to create temporary masscan output file: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(masscanOut.Name())

	nmapOut, err := ioutil.TempFile("", "nmap_output_*.xml")
	if err != nil {
		fmt.Printf("Error: Failed to create temporary nmap output file: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(nmapOut.Name())

	// Step 1: Run masscan
	fmt.Println("Running masscan...")
	cmd := exec.Command("sudo", "masscan", "-iL", *inputFile, "--ports", "0-65535", "--rate", "1000", "-oX", masscanOut.Name())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error: masscan failed to execute: %v\n", err)
		os.Exit(1)
	}

	// Check if masscan output was created
	if info, err := os.Stat(masscanOut.Name()); err != nil || info.Size() == 0 {
		fmt.Printf("Error: masscan output file %s is missing or empty\n", masscanOut.Name())
		os.Exit(1)
	}

	// Step 2: Process masscan output with XSLT
	fmt.Println("Processing masscan results...")
	portsTmp, err := ioutil.TempFile("", "ports_tmp_*.txt")
	if err != nil {
		fmt.Printf("Error: Failed to create temporary ports file: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(portsTmp.Name())

	if err := applyXSLT(masscanOut.Name(), masscanXSLT, portsTmp.Name()); err != nil {
		fmt.Printf("Error: Failed to process masscan output with XSLT: %v\n", err)
		content, _ := ioutil.ReadFile(masscanOut.Name())
		fmt.Printf("Contents of %s:\n%s\n", masscanOut.Name(), string(content))
		os.Exit(1)
	}

	// Check if ports_tmp.txt was created and is not empty
	if info, err := os.Stat(portsTmp.Name()); err != nil || info.Size() == 0 {
		fmt.Printf("Error: Failed to process masscan output or no open ports found\n")
		content, _ := ioutil.ReadFile(masscanOut.Name())
		fmt.Printf("Contents of %s:\n%s\n", masscanOut.Name(), string(content))
		os.Exit(1)
	}

	// Debug: Show contents of ports_tmp.txt
	portsContent, err := ioutil.ReadFile(portsTmp.Name())
	if err != nil {
		fmt.Printf("Error: Failed to read ports_tmp.txt: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Debug: Contents of %s:\n%s\n", portsTmp.Name(), string(portsContent))

	// Step 3: Run Nmap and process results
	fmt.Println("Running Nmap with Nmap integration...")
	finalOut, err := os.Create(*outputFile)
	if err != nil {
		fmt.Printf("Error: Failed to create output file %s: %v\n", *outputFile, err)
		os.Exit(1)
	}
	defer finalOut.Close()

	// Read ports_tmp.txt and process each IP:ports pair
	lines := strings.Split(strings.TrimSpace(string(portsContent)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			fmt.Printf("Warning: Invalid format in ports_tmp.txt: %s, skipping\n", line)
			continue
		}
		ip, ports := parts[0], parts[1]
		if ports == "" {
			fmt.Printf("Warning: No ports found for IP %s, skipping\n", ip)
			continue
		}

		fmt.Printf("Scanning IP %s with ports %s...\n", ip, ports)
		cmd := exec.Command("nmap", "-sV", "--version-light", "-n", "-p", ports, ip, "-oX", nmapOut.Name())
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: Nmap failed for IP %s, skipping: %v\n", ip, err)
			continue
		}

		// Check if Nmap output exists
		if info, err := os.Stat(nmapOut.Name()); err != nil || info.Size() == 0 {
			fmt.Printf("Warning: Nmap output for IP %s is missing or empty, skipping\n", ip)
			continue
		}

		// Process Nmap output with XSLT
		tmpResults, err := ioutil.TempFile("", "tmp_results_*.txt")
		if err != nil {
			fmt.Printf("Warning: Failed to create temporary results file for IP %s: %v\n", ip, err)
			continue
		}
		defer os.Remove(tmpResults.Name())

		if err := applyXSLT(nmapOut.Name(), nmapXSLT, tmpResults.Name()); err != nil {
			fmt.Printf("Warning: Failed to process Nmap output for IP %s: %v\n", ip, err)
			continue
		}

		// Check if tmp_results.txt exists and is not empty
		if info, err := os.Stat(tmpResults.Name()); err != nil || info.Size() == 0 {
			fmt.Printf("Warning: No valid output from Nmap for IP %s\n", ip)
			continue
		}

		// Append results to final output
		resultsContent, err := ioutil.ReadFile(tmpResults.Name())
		if err != nil {
			fmt.Printf("Warning: Failed to read tmp_results.txt for IP %s: %v\n", ip, err)
			continue
		}
		if _, err := finalOut.Write(resultsContent); err != nil {
			fmt.Printf("Warning: Failed to write to output file %s for IP %s: %v\n", *outputFile, ip, err)
			continue
		}
	}

	// Step 4: Display final output
	if info, err := os.Stat(*outputFile); err == nil && info.Size() > 0 {
		fmt.Printf("Final results saved to %s:\n", *outputFile)
		content, err := ioutil.ReadFile(*outputFile)
		if err != nil {
			fmt.Printf("Error: Failed to read final output file %s: %v\n", *outputFile, err)
			os.Exit(1)
		}
		fmt.Println(string(content))
	} else {
		fmt.Println("No results found. Check scan permissions or target availability.")
	}
}

// applyXSLT applies an XSLT transformation using xsltproc
func applyXSLT(inputXML, xsltContent, outputFile string) error {
	// Create temporary XSLT file
	xsltFile, err := ioutil.TempFile("", "xslt_*.xsl")
	if err != nil {
		return fmt.Errorf("failed to create temporary XSLT file: %v", err)
	}
	defer os.Remove(xsltFile.Name())

	if err := ioutil.WriteFile(xsltFile.Name(), []byte(xsltContent), 0644); err != nil {
		return fmt.Errorf("failed to write XSLT file %s: %v", xsltFile.Name(), err)
	}

	// Run xsltproc
	cmd := exec.Command("xsltproc", "-o", outputFile, xsltFile.Name(), inputXML)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run xsltproc: %v", err)
	}

	return nil
}
