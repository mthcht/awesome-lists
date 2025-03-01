rule Trojan_Win32_BazzarLdr_AA_2147775460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazzarLdr.AA!MTB"
        threat_id = "2147775460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazzarLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fuck Def" ascii //weight: 1
        $x_1_2 = "CLSID\\%1\\InprocHandler32" ascii //weight: 1
        $x_1_3 = "CLSID\\%1\\LocalServer32" ascii //weight: 1
        $x_1_4 = "%2\\protocol\\StdFileEditing\\server" ascii //weight: 1
        $x_1_5 = "[open(\"%1\")]" ascii //weight: 1
        $x_1_6 = "ddeexec" ascii //weight: 1
        $x_1_7 = "CryptEncrypt" ascii //weight: 1
        $x_1_8 = "CryptImportKey" ascii //weight: 1
        $x_1_9 = "CryptAcquireContextW" ascii //weight: 1
        $x_1_10 = "%s\\ShellNew" ascii //weight: 1
        $x_1_11 = "RSA2" ascii //weight: 1
        $x_1_12 = {2e 49 4e 49 00 00 00 00 2e 48 4c 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

