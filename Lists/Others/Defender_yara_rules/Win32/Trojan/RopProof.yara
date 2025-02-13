rule Trojan_Win32_RopProof_RPX_2147852529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RopProof.RPX!MTB"
        threat_id = "2147852529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RopProof"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ioser12" ascii //weight: 1
        $x_1_2 = "Java_com_sun_corba_se" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RopProof_RPX_2147852529_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RopProof.RPX!MTB"
        threat_id = "2147852529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RopProof"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {98 5b f1 e9 4b 1d 61 4e 4b da fc a7 6b f9 23 4f 3e 6a 59 fd 73 70 05 df 76 61 24 18 e6 ab 09 7d 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

