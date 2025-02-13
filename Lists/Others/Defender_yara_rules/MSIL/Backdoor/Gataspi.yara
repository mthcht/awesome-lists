rule Backdoor_MSIL_Gataspi_A_2147717155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Gataspi.A"
        threat_id = "2147717155"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gataspi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/SpyGate-RAT/" wide //weight: 5
        $x_1_2 = "Chat Succeeded Connected ..." wide //weight: 1
        $x_1_3 = "Screen Capture" wide //weight: 1
        $x_1_4 = "DDOS ATTACK" wide //weight: 1
        $x_1_5 = "USB Spread" wide //weight: 1
        $x_1_6 = "Skype Spread" wide //weight: 1
        $x_1_7 = "Inject Svchost" wide //weight: 1
        $x_1_8 = "Melt After Run" wide //weight: 1
        $x_1_9 = "RG|U|#|U|" wide //weight: 1
        $x_1_10 = "viewimage|U|" wide //weight: 1
        $x_1_11 = "Rename|U|File|U|" wide //weight: 1
        $x_1_12 = "openRG|U|" wide //weight: 1
        $x_1_13 = "openurl|U|" wide //weight: 1
        $x_1_14 = "sendfile|U|" wide //weight: 1
        $x_1_15 = "recv|U|" wide //weight: 1
        $x_1_16 = "Pic|*.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

