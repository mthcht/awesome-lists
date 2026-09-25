rule Ransom_Win64_FSociety_AMTB_2147969808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FSociety!AMTB"
        threat_id = "2147969808"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FSociety"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted by fsociety." ascii //weight: 1
        $x_1_2 = "We will DDoS your ISP and call your mom" ascii //weight: 1
        $x_1_3 = "[fsociety] Mission accomplished. Victim ID:" ascii //weight: 1
        $x_1_4 = "READ_ME_FSOCIETY.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_FSociety_A_2147978844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FSociety.A!AMTB"
        threat_id = "2147978844"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FSociety"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Fwallpaper.jpg" ascii //weight: 2
        $x_2_2 = ".FsocietyWins" ascii //weight: 2
        $x_2_3 = "Fsociety Society" ascii //weight: 2
        $x_1_4 = "Your files have been encrypted." ascii //weight: 1
        $x_1_5 = "FsocietyLock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

