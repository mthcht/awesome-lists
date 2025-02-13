rule Trojan_Win32_Fin7_A_2147752466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fin7.A!MTB!!Fin7.A!MTB"
        threat_id = "2147752466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fin7"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        info = "Fin7: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryption_key[i % encryption_key.length].charCodeAt(" ascii //weight: 1
        $x_1_2 = "group=ksoc._48370_2901&rt=512&secret=" ascii //weight: 1
        $x_1_3 = "shell.Run(\"%comspec% /c nslookup.exe -timeout=5 -retry=3 -type" ascii //weight: 1
        $x_1_4 = "select * from Win32_NetworkAdapterConfiguration where ipenabled = true" ascii //weight: 1
        $x_1_5 = "tp + \" \" + hst + \" \" + svr + \" > \" + ofile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

