rule Trojan_Win32_AppinElephant_LKV_2147896840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AppinElephant.LKV!MTB"
        threat_id = "2147896840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AppinElephant"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "temp\\elance\\AutoTransfer2\\Release\\AutoTransfer2.pdb" ascii //weight: 1
        $x_1_2 = "FtpPassword" wide //weight: 1
        $x_1_3 = "Sending ipconfig.exe output" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

