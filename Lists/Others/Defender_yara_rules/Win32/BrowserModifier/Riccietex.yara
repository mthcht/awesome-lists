rule BrowserModifier_Win32_Riccietex_227518_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Riccietex"
        threat_id = "227518"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Riccietex"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 71 71 62 72 6f 77 73 65 72 2e 65 2c 75 63 62 72 6f 77 73 65 72 00 2c 62 61 69 64 75 62 72 6f 77 73 65 72 00 2c 69 65 78 70 6c 6f 72 65 00 2c 74 68 65 77 6f 72 6c 64}  //weight: 1, accuracy: Low
        $x_1_2 = {73 6f 67 6f 75 65 78 70 6c 6f 72 65 72 2e 65 2c 32 33 34 35 65 78 70 6c 6f 72 65 72 00 2c 63 68 72 6f 6d 65 00 2c 6a 75 7a 69 00 2c 68 61 6f 31 32 33 6a 75 7a 69 00 2c 66 69 72 65 66 6f 78}  //weight: 1, accuracy: Low
        $x_1_3 = "Un_Ads" ascii //weight: 1
        $x_1_4 = "Un_MainPage" ascii //weight: 1
        $x_1_5 = "Chk_DesktopLink" ascii //weight: 1
        $x_1_6 = "Chk_HomePage" ascii //weight: 1
        $x_1_7 = "Chk_QuickLaunch" ascii //weight: 1
        $x_1_8 = "/read.php?t=" ascii //weight: 1
        $x_1_9 = {63 6e 7a 7a 2e 64 [0-4] 6f [0-4] 38 [0-4] 73 2e 63 6f 6d 2f 63 6f 72 65 2e 6a 73 3f 74 3d}  //weight: 1, accuracy: Low
        $x_1_10 = "KngStr_IAM" ascii //weight: 1
        $x_1_11 = "IAM_SETIEHP" ascii //weight: 1
        $x_1_12 = "IAM_DL" ascii //weight: 1
        $x_1_13 = "r e a d . p h  p ? t= a d s &d=" ascii //weight: 1
        $x_1_14 = "q q b  r o w  s e r  ,u c b  r o w  s e r  ,b a i  d u b  r o w  s e r  ,i e x  p l o  r e ,t h e  w o r  l d" ascii //weight: 1
        $x_1_15 = "s o g  o u e  x p l  o r e  r ,2 3 4  5 e x  p l o  r e r  ,c h r  o m e  ,j u z  i ,h a o  1 2 3  j u z  i ,f i r  e f o  x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

