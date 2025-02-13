rule TrojanDownloader_Win32_Murlo_AD_2147568919_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Murlo.AD"
        threat_id = "2147568919"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Murlo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EJwaLoadLibraryError" ascii //weight: 1
        $x_1_2 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_3 = "\\\\.\\LuoXue" ascii //weight: 1
        $x_1_4 = "\\drivers\\beep.sys" ascii //weight: 1
        $x_1_5 = "C:\\Program Files\\jjueA.exe" ascii //weight: 1
        $x_1_6 = "C:\\Program Files\\jjueB.exe" ascii //weight: 1
        $x_1_7 = "C:\\Program Files\\jjueC.exe" ascii //weight: 1
        $x_1_8 = "LoveHebe" ascii //weight: 1
        $x_1_9 = "\\Xue.exe" ascii //weight: 1
        $x_1_10 = "\\Device\\XueLuo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

