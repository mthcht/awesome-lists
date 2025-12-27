rule Ransom_Win64_Antoshka_SK_2147954320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Antoshka.SK!MTB"
        threat_id = "2147954320"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Antoshka"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your system has been blocked by the Antoshka virus," ascii //weight: 1
        $x_1_2 = "now it will sing you a song and blow away your Windows or virtual machine, you fucking faggots" ascii //weight: 1
        $x_1_3 = "AntoshkaMessageClass" ascii //weight: 1
        $x_1_4 = "Antoshka Says Hello!" ascii //weight: 1
        $x_1_5 = "antoshka_song.mp4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

