rule HackTool_Linux_Blitz_Gen_2147842705_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Blitz.Gen"
        threat_id = "2147842705"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Blitz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "---------------------->Faster than light<-----------------------------" ascii //weight: 1
        $x_1_2 = "--------------------->use only for testing<----------------------" ascii //weight: 1
        $x_1_3 = "Use: scan [OPTIONS] [[USER PASS]] FILE] [IPs/IPs Port FILE]" ascii //weight: 1
        $x_1_4 = "-t [NUMTHREADS]: Change the number of threads used. Default is " ascii //weight: 1
        $x_1_5 = "-m [MODE]: Change the way the scan works. Default is %d" ascii //weight: 1
        $x_1_6 = "-f [FINAL SCAN]: Does a final scan on found servers. Default is" ascii //weight: 1
        $x_1_7 = "Use -f 1 for A.B class /16. Default is 2 for A.B.C /24" ascii //weight: 1
        $x_1_8 = "-i [IP SCAN]: use -i 0 to scan ip class A.B. Default is %d" ascii //weight: 1
        $x_1_9 = "if you use -i 0 then use ./scan -p 22 -i 0 p 192.168 as agrumen" ascii //weight: 1
        $x_1_10 = "%-P 0 leave default password unchanged. Changes password by default" ascii //weight: 1
        $x_1_11 = "-s [TIMEOUT]: Change the timeout. Default is %ld" ascii //weight: 1
        $x_1_12 = "-p [PORT]: Specify another port to connect to. 0 for multiport" ascii //weight: 1
        $x_1_13 = "-c [REMOTE-COMMAND]: Command to execute on connect. Use ; or &&" ascii //weight: 1
        $x_1_14 = "Use: ./scan -t 202 -s 5 -S 5 -i 0 -p 22 p 192.168" ascii //weight: 1
        $x_1_15 = "honeypots and other limited linux devices will be skipped from the output" ascii //weight: 1
        $x_1_16 = "find ../../dota3.tar.gz. Proceeding without upload:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

