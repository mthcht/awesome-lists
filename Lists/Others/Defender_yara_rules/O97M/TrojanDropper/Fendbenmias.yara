rule TrojanDropper_O97M_Fendbenmias_A_2147730031_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Fendbenmias.A"
        threat_id = "2147730031"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Fendbenmias"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".UserId = Environ(\"USERDOMAIN\") & \"\\\" & Environ(\"USERNAME\")" ascii //weight: 1
        $x_3_2 = ";move $env:userprofile\\temp.ps1 $env:temp\\help.txt;" ascii //weight: 3
        $x_2_3 = "= \"Function Create-AesManagedObject{param([Object]$key,[Object]$IV)$aesManaged =" ascii //weight: 2
        $x_2_4 = "= $env:temp + 'smp.local.crt';$wcresults =" ascii //weight: 2
        $x_2_5 = "= Invoke-WebRequest -Uri $URL -WebSession $wrs -Method" ascii //weight: 2
        $x_2_6 = "= rootfld.GetTask(\"WinZip Updater\")" ascii //weight: 2
        $x_2_7 = "action.arguments = \"/c move \" & Environ(\"TEMP\") &" ascii //weight: 2
        $x_1_8 = "Call task.Run(0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

