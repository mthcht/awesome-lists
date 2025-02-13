rule Trojan_Win32_Syndicasec_2147727783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Syndicasec"
        threat_id = "2147727783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Syndicasec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\SysNative\\sysprep\\cryptbase.dll" ascii //weight: 1
        $x_1_2 = "WINDOWS\\system32\\sysprep\\cryptbase.dll" ascii //weight: 1
        $x_2_3 = "tmpinst.js" ascii //weight: 2
        $x_2_4 = "ProbeScriptFint" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Syndicasec_C_2147727825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Syndicasec.C"
        threat_id = "2147727825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Syndicasec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pGlobal->nOSType==64--%s\\cmd.exe %s" ascii //weight: 1
        $x_1_2 = "\\CryptBase.dll" ascii //weight: 1
        $x_1_3 = "gupdate.exe" ascii //weight: 1
        $x_1_4 = "wusa.exe" ascii //weight: 1
        $x_1_5 = "httpcom.log" ascii //weight: 1
        $x_1_6 = "%s%s.dll.cab" ascii //weight: 1
        $x_1_7 = "ReleaseEvildll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

