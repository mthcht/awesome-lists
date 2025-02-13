rule Ransom_Win32_RnToad_HL_2147771795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RnToad.HL!MTB"
        threat_id = "2147771795"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RnToad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files can only be retrived by entering the correct password." ascii //weight: 1
        $x_1_2 = "Wrong Password..buy it.." ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Ransomtoad" ascii //weight: 1
        $x_1_4 = "files have been encrypted" ascii //weight: 1
        $x_1_5 = "All your files belong to us!" ascii //weight: 1
        $x_1_6 = "RansomeToad.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

