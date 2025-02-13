rule VirTool_Win32_EmpirePy_A_2147836492_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/EmpirePy.A"
        threat_id = "2147836492"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "EmpirePy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subprocess.Popen(cmd" ascii //weight: 1
        $x_1_2 = ".communicate();" ascii //weight: 1
        $x_1_3 = ".request.ProxyHandler();" ascii //weight: 1
        $x_1_4 = "request.build_opener(" ascii //weight: 1
        $x_1_5 = ".addheaders=[('User-Agent'" ascii //weight: 1
        $x_1_6 = "=urllib.request.urlopen(req).read();" ascii //weight: 1
        $x_1_7 = "IV=a[0:4];" ascii //weight: 1
        $x_1_8 = "data=a[4:];" ascii //weight: 1
        $x_1_9 = "key=IV+'" ascii //weight: 1
        $x_1_10 = "+S[i]+key[i%len(key)])" ascii //weight: 1
        $x_1_11 = ".append(chr(char^S[" ascii //weight: 1
        $x_1_12 = "exec(''.join(" ascii //weight: 1
        $x_1_13 = {49 72 6f 6e 50 79 74 68 6f 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_14 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 00}  //weight: 1, accuracy: High
        $x_1_15 = {61 64 64 5f 41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 00}  //weight: 1, accuracy: High
        $x_1_16 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 00}  //weight: 1, accuracy: High
        $x_1_17 = {4d 69 63 72 6f 73 6f 66 74 2e 53 63 72 69 70 74 69 6e 67 2e 4d 65 74 61 64 61 74 61 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_18 = {54 68 72 65 61 64 53 74 61 72 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

