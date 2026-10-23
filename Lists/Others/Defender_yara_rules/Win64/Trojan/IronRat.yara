rule Trojan_Win64_IronRat_A_2147980892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IronRat.A!AMTB"
        threat_id = "2147980892"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IronRat"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "rat.ironrat.de5.net" ascii //weight: 2
        $x_2_2 = "steal sent" ascii //weight: 2
        $x_2_3 = "X-IR-License:" ascii //weight: 2
        $x_2_4 = "Global\\IR_agent_single" ascii //weight: 2
        $n_100_5 = "Uninst.exe" ascii //weight: -100
        $n_100_6 = "Uninstaller.exe" ascii //weight: -100
        $n_100_7 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

