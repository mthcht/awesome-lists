rule Trojan_Win32_SuspNodeJsExec_A_2147965334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspNodeJsExec.A"
        threat_id = "2147965334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspNodeJsExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-32] 73 00 74 00 61 00 72 00 74 00 [0-48] 2f 00 6d 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\\AppData\\Roaming\\NodeJs\\node.exe" wide //weight: 1
        $x_1_3 = {5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-96] 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspNodeJsExec_G_2147969276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspNodeJsExec.G"
        threat_id = "2147969276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspNodeJsExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-32] 73 00 74 00 61 00 72 00 74 00 [0-48] 2f 00 6d 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = "\\AppData\\Local\\NodeJs\\node.exe" wide //weight: 1
        $x_1_3 = {5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-96] 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

