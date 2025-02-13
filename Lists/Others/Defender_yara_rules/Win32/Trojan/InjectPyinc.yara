rule Trojan_Win32_InjectPyinc_SA_2147734336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InjectPyinc.SA"
        threat_id = "2147734336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InjectPyinc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spyiboot01_bootstrap" ascii //weight: 1
        $x_1_2 = "bCrypto.Cipher._AES.pyd" ascii //weight: 1
        $x_1_3 = "bii.exe.manifest" ascii //weight: 1
        $x_1_4 = "\\_MEI38042\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

