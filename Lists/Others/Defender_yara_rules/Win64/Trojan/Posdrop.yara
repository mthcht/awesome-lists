rule Trojan_Win64_Posdrop_A_2147735892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Posdrop.A!dha"
        threat_id = "2147735892"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Posdrop"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Microsoft\\HelpAssistant\\btid.dat" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\HelpAssistant\\btdata.txt" ascii //weight: 1
        $x_1_3 = "ns.akamai1811.com" ascii //weight: 1
        $x_1_4 = "api.ipify.org" ascii //weight: 1
        $x_1_5 = "Temp\\memscrp.stp" ascii //weight: 1
        $x_1_6 = ".stopped" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

