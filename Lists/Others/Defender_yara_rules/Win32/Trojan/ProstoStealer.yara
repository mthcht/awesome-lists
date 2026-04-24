rule Trojan_Win32_ProstoStealer_AMTB_2147967695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProstoStealer!AMTB"
        threat_id = "2147967695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProstoStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Jabber\\psi.txt" ascii //weight: 2
        $x_2_2 = "\\Psi\\profiles\\default\\accounts.xml" ascii //weight: 2
        $x_1_3 = "sCB.cards.%u.txt" ascii //weight: 1
        $x_1_4 = "sCB.passwords.%u.txt" ascii //weight: 1
        $x_1_5 = "prosto_stealer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

