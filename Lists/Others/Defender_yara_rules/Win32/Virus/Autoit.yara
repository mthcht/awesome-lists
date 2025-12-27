rule Virus_Win32_Autoit_EA_2147957159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Autoit.EA!MTB"
        threat_id = "2147957159"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Autoit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Mau virus" ascii //weight: 2
        $x_1_2 = "RunDOS (\"AT /delete /yes\")" ascii //weight: 1
        $x_1_3 = "RegDelete (\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "Explorer\\WorkgroupCrawler\\Shares" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

