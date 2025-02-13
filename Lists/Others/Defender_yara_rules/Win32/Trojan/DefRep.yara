rule Trojan_Win32_DefRep_DA_2147916986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefRep.DA!MTB"
        threat_id = "2147916986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefRep"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "54"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "Get-WmiObject -Namespace 'root\\SecurityCenter2' -Class" wide //weight: 1
        $x_50_3 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 20 00 2d 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 4e 00 61 00 6d 00 65 00 [0-100] 64 00 69 00 73 00 70 00 6c 00 61 00 79 00 4e 00 61 00 6d 00 65 00 20 00 2d 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 20 00 27 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 27 00}  //weight: 50, accuracy: Low
        $x_1_4 = "mshta" wide //weight: 1
        $x_1_5 = "https://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

