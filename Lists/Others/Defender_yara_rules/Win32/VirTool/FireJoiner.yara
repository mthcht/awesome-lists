rule VirTool_Win32_FireJoiner_A_2147602470_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/FireJoiner.A!dr"
        threat_id = "2147602470"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "FireJoiner"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "150"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {6a 22 8d 4d 94 51 ff d7 c7 85 7c ff ff ff ?? ?? ?? ?? bb 08 00 00 00 89 9d 74 ff ff ff}  //weight: 100, accuracy: Low
        $x_10_2 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS\\" wide //weight: 10
        $x_10_3 = "metsyS\\seiciloP\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS\\" wide //weight: 10
        $x_10_4 = "erotseRmetsyS\\noisreVtnerruC\\TN swodniW\\tfosorciM\\ERAWTFOS\\" wide //weight: 10
        $x_10_5 = "rgMwF.gfCteNH" wide //weight: 10
        $x_1_6 = "taskkill /f /im ApVxdWin.exe" wide //weight: 1
        $x_1_7 = "taskkill /f /im AVENGINE.exe" wide //weight: 1
        $x_1_8 = "taskkill /f /im pavsrv51.exe" wide //weight: 1
        $x_1_9 = "taskkill /f /im psimreal.exe" wide //weight: 1
        $x_1_10 = "taskkill /f /im PsImSvc.exe" wide //weight: 1
        $x_1_11 = "taskkill /f /im WebProxy.exe" wide //weight: 1
        $x_1_12 = "taskkill /f /im mcagent.exe" wide //weight: 1
        $x_1_13 = "taskkill /f /im mcdash.exe" wide //weight: 1
        $x_1_14 = "taskkill /f /im mghtml.exe" wide //weight: 1
        $x_1_15 = "taskkill /f /im mcmnhdlr.exe" wide //weight: 1
        $x_1_16 = "taskkill /f /im mcvsshld.exe" wide //weight: 1
        $x_1_17 = "taskkill /f /im McVSEscn.exe" wide //weight: 1
        $x_1_18 = "taskkill /f /im mcvsftsn.exe" wide //weight: 1
        $x_1_19 = "/v egui /f" wide //weight: 1
        $x_1_20 = "/v APVXDWIN /f" wide //weight: 1
        $x_1_21 = "/v MCAgentExe /f" wide //weight: 1
        $x_1_22 = "/v McRegWiz /f" wide //weight: 1
        $x_1_23 = "/v MCUpdateExe /f" wide //weight: 1
        $x_1_24 = "/v CleanUp /f" wide //weight: 1
        $x_1_25 = "/v VirusScan Online /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*) and 20 of ($x_1_*))) or
            ((1 of ($x_100_*) and 4 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

