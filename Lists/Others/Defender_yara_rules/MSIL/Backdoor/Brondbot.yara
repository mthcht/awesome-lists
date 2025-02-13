rule Backdoor_MSIL_Brondbot_A_2147656002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Brondbot.A"
        threat_id = "2147656002"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Brondbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_isfucked" ascii //weight: 1
        $x_1_2 = "Miner started!" wide //weight: 1
        $x_1_3 = "UAC is Disabled!" wide //weight: 1
        $x_1_4 = {73 00 79 00 73 00 69 00 6e 00 66 00 6f 00 [0-4] 76 00 69 00 73 00 69 00 74 00 [0-4] 62 00 69 00 74 00 63 00 6f 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_5 = "bitcoin-miner.exe" wide //weight: 1
        $x_1_6 = "UdpFlood" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

