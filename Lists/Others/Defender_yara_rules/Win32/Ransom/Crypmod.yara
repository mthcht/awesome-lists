rule Ransom_Win32_Crypmod_A_2147734432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crypmod.A!bit"
        threat_id = "2147734432"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypmod"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c6 0f b6 c9 2b c1 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 41 3b c1 7f 07 8b c6 a3}  //weight: 1, accuracy: Low
        $x_1_2 = {88 04 0a 0f b7 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 42 3b 55 ?? 0f 8c ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crypmod_B_2147734493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crypmod.B!bit"
        threat_id = "2147734493"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypmod"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 80 e2 ?? 02 d2 02 d2 08 11 8b 0c 24 8a d0 d2 e2 8b 4c 24 ?? c0 e0 ?? 80 e2 ?? 08 11 8b 4c 24 ?? 08 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 11 0f b6 0c 1a 8d 04 1a 0f b6 50 ?? 88 54 24 ?? 0f b6 50 ?? 88 4c 24 ?? 0f b6 48 [0-33] e8 ?? ?? ?? ?? 8a 44 24 ?? 0f b6 4c 24 ?? 0f b6 54 24 ?? 88 04 3e 46 88 0c 3e 46 88 14 3e 83 c3 ?? 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crypmod_MK_2147760348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crypmod.MK!MTB"
        threat_id = "2147760348"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypmod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".zip" ascii //weight: 1
        $x_1_2 = "%d + %d = %d" ascii //weight: 1
        $x_1_3 = "echo Ops, seus arquivos foram criptografados" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crypmod_MK_2147760348_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crypmod.MK!MTB"
        threat_id = "2147760348"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypmod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = ".avi.css.doc.gif.htm.jpg.mov.mp3.mp4.mpg.pdf.png.ppt.rar.svg.txt.xls.xml.zip" ascii //weight: 1
        $x_1_3 = {84 02 0f b6 33 43 45 31 c6 96 0f b6 c0 96 8b 34 b2 c1 e8 ?? 31 f0 39 cd 7c e6}  //weight: 1, accuracy: Low
        $x_1_4 = "hijacked" ascii //weight: 1
        $x_1_5 = "README.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crypmod_MAK_2147793935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crypmod.MAK!MTB"
        threat_id = "2147793935"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypmod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 b9 0a 00 00 00 99 f7 f9 80 c2 [0-1] 0f b6 c3 88 14 07 b9 0a 00 00 00 8b c6 99 f7 f9 89 c6 4b 85 f6 75 dc}  //weight: 1, accuracy: Low
        $x_1_2 = "ReadMe.txt" ascii //weight: 1
        $x_1_3 = "Recovery.bmp" ascii //weight: 1
        $x_1_4 = "$RECYCLE.BIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

