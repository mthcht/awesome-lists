rule Trojan_Win32_Separ_RB_2147844181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Separ.RB!MTB"
        threat_id = "2147844181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Separ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eIORKpvAAzYe1eh6pdr2Den3cpq6MkfTCjSQxdqjRrddQtSdcmVNEEzTOUenjSM36JivcydpvsoVqyMB3Ek1OrxOAfZGF3dgJ8a0HWDSKX6sp67iC6d2Ucu" ascii //weight: 1
        $x_1_2 = "jhdfkldfhndfkjdfnbfklfnf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Separ_GMD_2147853505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Separ.GMD!MTB"
        threat_id = "2147853505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Separ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@jhdfkldfhndfkjdfnbfklfnf@NetsealIsTheBestLi" ascii //weight: 1
        $x_1_2 = "ivcydpvsoVqyMB3Ek1OrxOAfZGF3dgJ8" ascii //weight: 1
        $x_1_3 = "a0HWDSKX6sp67iC6" ascii //weight: 1
        $x_1_4 = "SciTE.EXE" ascii //weight: 1
        $x_1_5 = "ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

