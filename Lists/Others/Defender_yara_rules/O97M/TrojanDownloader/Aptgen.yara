rule TrojanDownloader_O97M_Aptgen_A_2147731852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Aptgen.A"
        threat_id = "2147731852"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Aptgen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = uspacut(\"Dnaenacnarnaynapnatnainaonanna" ascii //weight: 1
        $x_1_2 = " = ikoxs(\"Dpasepascpasrpasypasppastpasipasopasnpas" ascii //weight: 1
        $x_1_3 = " = Replace(\"Doheohcohrohyohpohtohiohoohnoh" ascii //weight: 1
        $x_1_4 = " = Replace(\"Dnuplenuplcnuplrnuplynuplpnupltnuplinuplonuplnnupl" ascii //weight: 1
        $x_1_5 = " = jtykpype.GetFolder(agulu.expandEnvironmentStrings(\"%PROGRAMFILES%\"))" ascii //weight: 1
        $x_1_6 = {71 20 3d 20 45 6e 76 69 72 6f 6e 28 22 75 73 65 72 70 72 6f 66 69 6c 65 22 29 20 26 20 70 28 32 29 0d 0a 46 69 6c 65 43 6f 70 79 20 70 28 31 29 2c 20 71 0d 0a 53 68 65 6c 6c 20 71 20 26 20 70 28 33 29 2c 20 30}  //weight: 1, accuracy: High
        $x_1_7 = "ssugym = \"wscri\" & bxeko & \"xe \" & otkybw & \"script \" & wolyx" ascii //weight: 1
        $x_1_8 = "caczwc = Array(367, 358, 367, 371, 358, 363, 364, 367, 358)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

