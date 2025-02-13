rule Trojan_MSIL_Gotup_A_2147723323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gotup.A!bit"
        threat_id = "2147723323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gotup"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "V354ApKFZzkIB4D4E3pUUjbyui2JgXJzyBtuWt9brUFWP5iT" wide //weight: 1
        $x_1_2 = "powershell.exe -Command iex" wide //weight: 1
        $x_1_3 = "E19AD4B2580B={0}&EFF0BCFAA={1}&HC619F6C1A={2}&A27BF6210={3}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

