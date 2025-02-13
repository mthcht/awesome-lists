rule Backdoor_MSIL_Dictaor_A_2147692764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Dictaor.A"
        threat_id = "2147692764"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dictaor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bigscreen_" ascii //weight: 1
        $x_1_2 = "Camerast_" ascii //weight: 1
        $x_1_3 = "downloaderx_" ascii //weight: 1
        $x_1_4 = "fileupload_" ascii //weight: 1
        $x_1_5 = "kloge_" ascii //weight: 1
        $x_1_6 = "onlineloger_" ascii //weight: 1
        $x_1_7 = "Shell_" ascii //weight: 1
        $x_1_8 = "smallcrn_" ascii //weight: 1
        $x_1_9 = "Filemang_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_MSIL_Dictaor_A_2147692764_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Dictaor.A"
        threat_id = "2147692764"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dictaor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<ANTI_VER>No anti virus.</ANTI_VER>" wide //weight: 1
        $x_1_2 = "CAM:SCR<" wide //weight: 1
        $x_1_3 = "KILL<ALL*" wide //weight: 1
        $x_1_4 = "onlog:scr=<s-scr>" wide //weight: 1
        $x_1_5 = "\\dumpshell.sh" wide //weight: 1
        $x_1_6 = ":DOWM::jop::DONE:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

