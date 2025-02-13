rule Trojan_Win32_Lodbak_S_2147756307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lodbak.S!MSR"
        threat_id = "2147756307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lodbak"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\shane1\\dizzy\\mongoose\\ruiigeqr.pdb" ascii //weight: 1
        $x_1_2 = "ruiigeqr.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lodbak_MBER_2147896059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lodbak.MBER!MTB"
        threat_id = "2147896059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lodbak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gw16BRWbrw16MRWQ" ascii //weight: 1
        $x_1_2 = "baalqihxvkubdqm" ascii //weight: 1
        $x_1_3 = "czdihofbznvf" ascii //weight: 1
        $x_1_4 = "ltgkkdtubgip" ascii //weight: 1
        $x_1_5 = "wslegxufdnporo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

