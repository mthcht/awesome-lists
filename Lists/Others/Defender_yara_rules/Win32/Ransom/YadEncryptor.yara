rule Ransom_Win32_YadEncryptor_PAB_2147776979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/YadEncryptor.PAB!MTB"
        threat_id = "2147776979"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "YadEncryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cheia privata a fost distrusa. YAD A INVINS." ascii //weight: 1
        $x_1_2 = "@\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_3 = "GetDiskFreeSpaceExA" ascii //weight: 1
        $x_1_4 = "YAD Ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

