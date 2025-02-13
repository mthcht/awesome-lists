rule TrojanDownloader_Win32_Seraph_PAAP_2147848843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Seraph.PAAP!MTB"
        threat_id = "2147848843"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://rp.myl23.com/api.jsp" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_3 = "i am avp" ascii //weight: 1
        $x_1_4 = "://live.myl23.com/install.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Seraph_PAAG_2147850038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Seraph.PAAG!MTB"
        threat_id = "2147850038"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL2ltZ2NhY2hlLmNsb3Vkc2VydmljZXNkZXZjLnRrL3BpY3R1cmVzcy8yMDIzLw==" ascii //weight: 1
        $x_1_2 = "imgcache.cloudservicesdevc.tk/picturess/2023/RDSv38.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Seraph_PABQ_2147894311_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Seraph.PABQ!MTB"
        threat_id = "2147894311"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//155.94.129.4/zijiluoli.bin" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\2c2ao.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

