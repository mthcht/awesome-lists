rule Trojan_Win32_Novcod_A_2147629133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Novcod.A"
        threat_id = "2147629133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Novcod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fatal Error!  The media system on your computer is corrupt." ascii //weight: 1
        $x_1_2 = "Warning! Your media codec is out of date." ascii //weight: 1
        $x_1_3 = {2f 70 75 72 63 68 61 73 65 2e 70 68 70 3f 69 64 3d 37 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 73 74 79 6b 2e 70 68 70 3f 69 64 3d 37 00}  //weight: 1, accuracy: High
        $x_1_5 = "Windows can't play the following media formats:" ascii //weight: 1
        $x_1_6 = "AVI;ASF;WMV;AVS;FLV;MKV;MOV;3GP;MP4;MPG;MPEG;MP3;AAC;WAV;WMA;CDA;FLAC;M4A;MID." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

