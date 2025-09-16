rule Trojan_Win32_DiskCoder_Z_2147952303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiskCoder.Z!MTB"
        threat_id = "2147952303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiskCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c7 c1 c0 07 44 33 c8 8b 45 7f 41 03 c1 c1 c0 09 44 33 f0 43 8d 04 0e c1 c0 0d 33 f8 89 3c 24 41 8d 04 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

