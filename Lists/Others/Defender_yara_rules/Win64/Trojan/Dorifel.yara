rule Trojan_Win64_Dorifel_MKV_2147911514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dorifel.MKV!MTB"
        threat_id = "2147911514"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dorifel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 ?? 03 d0 0f be c2 6b d0 3a 0f b6 c1 2a c2 04 37 41 30 00 ff c1 4d 8d 40 01 83 f9 26 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dorifel_VD_2147975378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dorifel.VD!MTB"
        threat_id = "2147975378"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dorifel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://387218192.fwh.is/?i=1" wide //weight: 1
        $x_1_2 = "https://CockeoRoblox.wuaze.com" wide //weight: 1
        $x_1_3 = "https://share.google/UhyTVooeXFlez5aFe" wide //weight: 1
        $x_1_4 = "start /min wmplayer \"musique.mp3\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

