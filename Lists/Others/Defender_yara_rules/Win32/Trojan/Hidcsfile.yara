rule Trojan_Win32_Hidcsfile_A_2147643447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hidcsfile.A"
        threat_id = "2147643447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hidcsfile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%windir%\\Offline Web Pages\\ico\\" ascii //weight: 1
        $x_1_2 = "\\Offline Web Pages\\web\\web.exe  \"\"%1\"\" %*" ascii //weight: 1
        $x_1_3 = {49 65 78 70 6c 6f 72 65 2e 65 78 65 5f 5f 5f 0d 0a 2f 2f 5f 5f 5f 5f 68 74 74 70 3a 2f 2f 77 77 77 2e 74 61 6f 62 61 6f 2e 63 6f 6d 2f}  //weight: 1, accuracy: High
        $x_1_4 = "http://%64%68%2E%64%68%39%31%39%2E%63%6F%6D/?id=" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Classes\\dcsfile\\ScriptEngine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

