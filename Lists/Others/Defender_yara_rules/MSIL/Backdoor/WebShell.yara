rule Backdoor_MSIL_WebShell_GMF_2147888715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GMF!MTB"
        threat_id = "2147888715"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 00 65 00 69 00 7a 00 68 00 69 00 2e 00 69 00 6e}  //weight: 1, accuracy: High
        $x_1_2 = "FaKe Shell By F4k3r" ascii //weight: 1
        $x_1_3 = "cmd.exe /c net user" ascii //weight: 1
        $x_1_4 = "cyRCbLv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_GMH_2147889019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GMH!MTB"
        threat_id = "2147889019"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "App_global.asax.yx6areqw" ascii //weight: 1
        $x_1_2 = "System.Text" ascii //weight: 1
        $x_1_3 = "root\\850b8287\\ae2d3fe9" ascii //weight: 1
        $x_1_4 = "CrmManagement/MemberManagement/SystemSet/HouseSet/BatchUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_AF_2147889324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.AF!MTB"
        threat_id = "2147889324"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://jc.pickypams.com/" wide //weight: 1
        $x_1_2 = "e6789aa748724a8fc57743df6852679d" wide //weight: 1
        $x_1_3 = "IIS://localhost/W3SVC" wide //weight: 1
        $x_1_4 = "Backdoor" wide //weight: 1
        $x_1_5 = "Bin_Button_KillMe" wide //weight: 1
        $x_1_6 = "File attributes modify success!" wide //weight: 1
        $x_1_7 = "Process Kill Success !" wide //weight: 1
        $x_1_8 = "Clear All Thread ......" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_AG_2147889342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.AG!MTB"
        threat_id = "2147889342"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "21232f297a57a5a743894a0e4a801fc3" wide //weight: 1
        $x_1_2 = "IIS://localhost/W3SVC" wide //weight: 1
        $x_1_3 = "Aspx/EN/ueftInvester.aspx" wide //weight: 1
        $x_1_4 = "Bin_Button_KillMe" wide //weight: 1
        $x_1_5 = "root\\9f43385f\\35dfbd2e" ascii //weight: 1
        $x_1_6 = "Directory created success !" wide //weight: 1
        $x_1_7 = "Process Kill Success !" wide //weight: 1
        $x_1_8 = "Clear All Thread ......" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_GMP_2147892748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GMP!MTB"
        threat_id = "2147892748"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "App_global.asax.svwnzjkj" ascii //weight: 1
        $x_1_2 = "Backdoor" ascii //weight: 1
        $x_1_3 = "uXevN" ascii //weight: 1
        $x_1_4 = "Create_ASP_memberservice_ajax_404_aspx" ascii //weight: 1
        $x_1_5 = "SP_oamethod exec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_GMQ_2147892830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GMQ!MTB"
        threat_id = "2147892830"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "App_global.asax.-romko_e" ascii //weight: 1
        $x_1_2 = "App_Web_hijsba9i" ascii //weight: 1
        $x_1_3 = "SP_oamethod exec" ascii //weight: 1
        $x_1_4 = "oJiym" ascii //weight: 1
        $x_1_5 = "Backdoor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_GND_2147893567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GND!MTB"
        threat_id = "2147893567"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 06 6f ?? ?? ?? 0a 07 16 07 8e 69 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 5d 00 00 70 6f ?? ?? ?? 0a 02 6f ?? ?? ?? 0a 26 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "asnuylbgaubb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_AH_2147893654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.AH!MTB"
        threat_id = "2147893654"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bdbca288fee7f92f2bfa9f7012727740" wide //weight: 1
        $x_1_2 = "IIS://localhost/W3SVC" wide //weight: 1
        $x_1_3 = "Backdoor" wide //weight: 1
        $x_1_4 = "Bin_Button_KillMe" wide //weight: 1
        $x_1_5 = "File attributes modify success!" wide //weight: 1
        $x_1_6 = "Process Kill Success !" wide //weight: 1
        $x_1_7 = "Clear All Thread ......" wide //weight: 1
        $x_1_8 = "File time clone success!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_GNE_2147895965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GNE!MTB"
        threat_id = "2147895965"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 06 6f ?? ?? ?? 0a 07 16 07 8e 69 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 a6 01 00 70 6f ?? ?? ?? 0a 02 ?? ?? ?? 00 0a 26 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "asnuylbgaubb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_GNF_2147896319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GNF!MTB"
        threat_id = "2147896319"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 02 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 00 de 05}  //weight: 10, accuracy: Low
        $x_1_2 = "images/ad/imgCustomBg.aspx" ascii //weight: 1
        $x_1_3 = "scbyzh_aspx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_WebShell_GNC_2147897193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GNC!MTB"
        threat_id = "2147897193"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 06 6f ?? ?? ?? 0a 07 16 07 8e 69 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 5d 00 00 70 6f ?? ?? ?? 0a 02 6f ?? ?? ?? 0a 26 2a}  //weight: 10, accuracy: Low
        $x_1_2 = {41 70 70 5f 57 65 62 5f [0-22] 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_GMB_2147897206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GMB!MTB"
        threat_id = "2147897206"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 07 16 11 07 8e 69 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 06 09 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 de 03 26 de 00 06 6f ?? ?? ?? 0a 2a}  //weight: 10, accuracy: Low
        $x_1_2 = {41 70 70 5f 57 65 62 5f [0-22] 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_GMC_2147897297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GMC!MTB"
        threat_id = "2147897297"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 08 09 6f ?? ?? ?? 0a 26 08 02 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 08 07 6f ?? ?? ?? 0a 26 08 6f ?? ?? ?? 0a 26 09 6f ?? ?? ?? 0a 13 04 09 6f ?? ?? ?? 0a 02 6f ?? ?? ?? 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_AI_2147899626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.AI!MTB"
        threat_id = "2147899626"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 06 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 28 ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 02 6f ?? 00 00 0a 26 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "8edb23160d1571a0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_AK_2147900001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.AK!MTB"
        threat_id = "2147900001"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 08 16 1f 30 9c 08 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 02 28 ?? 00 00 0a 02 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 06 06 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 07 8e 69 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 02 6f ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_AL_2147900168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.AL!MTB"
        threat_id = "2147900168"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0d 08 09 6f ?? 00 00 0a 26 08 07 6f ?? 00 00 0a 26 08 6f ?? 00 00 0a 26 09 6f ?? 00 00 0a 13 ?? 09 6f ?? 00 00 0a 00 02 6f}  //weight: 2, accuracy: Low
        $x_2_2 = "{payloadStoreName}" wide //weight: 2
        $x_1_3 = "3c6e0b8a9c15224a" wide //weight: 1
        $x_1_4 = "30e724cfc1b7b28c" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_WebShell_AM_2147900169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.AM!MTB"
        threat_id = "2147900169"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 02 28 ?? 00 00 0a 02 28 ?? 00 00 0a 6f [0-2] 00 0a 6f [0-2] 00 0a 0c 73 [0-2] 00 0a 07 07 6f [0-2] 00 0a 08 16 08 8e 69 6f [0-2] 00 0a 28 [0-2] 00 0a 72 ?? ?? ?? 70 6f [0-2] 00 0a 02 6f [0-2] 00 0a 26}  //weight: 4, accuracy: Low
        $x_1_2 = "8c0d0e836ab62f65" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_GMZ_2147900506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GMZ!MTB"
        threat_id = "2147900506"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 19 9a 17 28 ?? ?? ?? 0a 0b 26 28 ?? ?? ?? 0a 26 02 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 74 ?? ?? ?? ?? 7b ?? ?? ?? ?? 25 16 03 a2 25 17 04 a2 25 18 06 a2 25 19 07 a2 26}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_AO_2147911769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.AO!MTB"
        threat_id = "2147911769"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 10 01 73 ?? 00 00 0a 0b 07 18 6f ?? 00 00 0a 07 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 07 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "e45e329feb5d925b" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = {41 00 70 00 70 00 5f 00 57 00 65 00 62 00 5f 00 [0-10] 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_WebShell_ASQ_2147924498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.ASQ!MTB"
        threat_id = "2147924498"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0b 38 ?? 00 00 00 00 02 1d 8d ?? 00 00 01 13 05 11 05 16 72 ?? ?? 00 70 a2 11 05 17 02 06 07 9a 28 ?? 00 00 06 a2 11 05 18 72 ?? ?? 00 70 a2 11 05 19 07 8c ?? 00 00 01 a2 11 05 1a 72 ?? ?? 00 70 a2 11 05 1b 06 07 9a a2 11 05 1c}  //weight: 2, accuracy: Low
        $x_1_2 = "Clear All Thread ...." wide //weight: 1
        $x_1_3 = "8f34b0861bce1e0536a2a3d33c7a0f39" wide //weight: 1
        $x_1_4 = "Process Kill Success !" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_GNS_2147927840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GNS!MTB"
        threat_id = "2147927840"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 06 16 6f ?? ?? ?? 0a 00 06 28 ?? ?? ?? 0a 0b 07 6f ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 0d 08 6f ?? ?? ?? 0a 00 09 13 04 2b 00 11 04 2a}  //weight: 5, accuracy: Low
        $x_5_2 = {20 c8 85 6a 9f 0a 2b 00 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_WebShell_GTB_2147939787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/WebShell.GTB!MTB"
        threat_id = "2147939787"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 11 07 6f ?? 00 00 0a 13 08 11 07 6f ?? 00 00 0a 00 02 6f ?? 00 00 0a 6f ?? 00 00 0a 73 ?? 00 00 0a 08 08 6f ?? 00 00 0a 11 08 16 11 08 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 00 00 00 de 05 26 00 00 de 00 00 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

