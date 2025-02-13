rule Trojan_Win32_ReflectiveLoader_EC_2147903617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ReflectiveLoader.EC!MTB"
        threat_id = "2147903617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ReflectiveLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svchost.exe" ascii //weight: 1
        $x_1_2 = "HajackPath:%s" ascii //weight: 1
        $x_1_3 = "RunDownLoaderDll" ascii //weight: 1
        $x_1_4 = "/c del" ascii //weight: 1
        $x_1_5 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_6 = "FileMgr::ShareFilesInMemory" ascii //weight: 1
        $x_1_7 = "DownloadClient::WorkThread" ascii //weight: 1
        $x_1_8 = "PolicyMgr::Start" ascii //weight: 1
        $x_1_9 = "PolicyMgr::DownloadPolicy" ascii //weight: 1
        $x_1_10 = "PolicyMgr::DownloadPolicyReponse" ascii //weight: 1
        $x_1_11 = "ReflectiveLoader32.pdb" ascii //weight: 1
        $x_1_12 = "ReflectiveLoader32.dll" ascii //weight: 1
        $x_1_13 = "_ReflectiveLoader@20" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

