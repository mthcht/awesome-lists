rule Ransom_Win32_RyukPacker_2147775361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RyukPacker!MTB"
        threat_id = "2147775361"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RyukPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fuck Def" ascii //weight: 1
        $x_1_2 = "CLSID\\%1\\InprocHandler32" ascii //weight: 1
        $x_1_3 = "CLSID\\%1\\LocalServer32" ascii //weight: 1
        $x_1_4 = "%2\\protocol\\StdFileEditing\\server" ascii //weight: 1
        $x_1_5 = "[open(\"%1\")]" ascii //weight: 1
        $x_1_6 = "ddeexec" ascii //weight: 1
        $x_1_7 = "NetQueryDisplayInformation" ascii //weight: 1
        $x_1_8 = "CryptEncrypt" ascii //weight: 1
        $x_1_9 = "CryptImportKey" ascii //weight: 1
        $x_1_10 = "CryptAcquireContextW" ascii //weight: 1
        $x_1_11 = "GetUserNames" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

