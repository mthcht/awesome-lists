rule Trojan_Win32_Frockafob_C_2147805717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Frockafob.C"
        threat_id = "2147805717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Frockafob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TrickBotClientExe.pdb" ascii //weight: 1
        $x_1_2 = "/50/cmd=" ascii //weight: 1
        $x_1_3 = "Succsefully executed:" ascii //weight: 1
        $x_1_4 = "/camp1/" ascii //weight: 1
        $x_1_5 = "get-file" ascii //weight: 1
        $x_1_6 = "calling put file" ascii //weight: 1
        $x_1_7 = "TrickBot-Implant" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

