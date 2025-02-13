rule Ransom_Win64_BlackShadow_YAA_2147892102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackShadow.YAA!MTB"
        threat_id = "2147892102"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackShadow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b fa 8b ca c1 c7 0f c1 c1 0d 33 f9 c1 ea 0a 33 fa 8b ce 8b d6 c1 c9 07 c1 c2 0e 33 d1 c1 ee 03 33 d6 03 fa}  //weight: 1, accuracy: High
        $x_1_2 = "-Command Remove -Item 'd:\\$RECYCLE.BIN" wide //weight: 1
        $x_1_3 = "vssadmin.exe delete shadows /all /quiet" wide //weight: 1
        $x_1_4 = "SCHTASKS.exe /Delete /TN \"Windows Update BETA" wide //weight: 1
        $x_1_5 = "Number Of Files Encrypted:" wide //weight: 1
        $x_1_6 = "Number Of Files Sent:" wide //weight: 1
        $x_1_7 = "-priority" wide //weight: 1
        $x_1_8 = "-skip" wide //weight: 1
        $x_1_9 = "-power" wide //weight: 1
        $x_1_10 = "-nodel" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

