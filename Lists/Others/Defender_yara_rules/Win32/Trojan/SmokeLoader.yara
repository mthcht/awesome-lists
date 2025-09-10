rule Trojan_Win32_SmokeLoader_PA_2147750067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PA!MTB"
        threat_id = "2147750067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 08 8b 45 ?? 01 45 ?? 8b c3 c1 e0 04 03 c6 33 45 08 33 45 0c 50 8d 45 f4 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PA_2147750067_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PA!MTB"
        threat_id = "2147750067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc 83 c2 01 89 55 fc 81 7d fc 40 14 00 00 73 29 8b 45 fc 0f be 88 ?? ?? ?? 00 8b 45 fc 33 d2 be 20 00 00 00 f7 f6 0f be 92 ?? ?? ?? 00 33 ca 8b 45 f8 03 45 fc 88 08 eb c5}  //weight: 10, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 68 40 14 00 00 6a 00 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PB_2147757177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PB!MTB"
        threat_id = "2147757177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@bangPrecision@4" ascii //weight: 1
        $x_1_2 = "@plusTokenAfter@4" ascii //weight: 1
        $x_1_3 = "@yurii@4" ascii //weight: 1
        $x_1_4 = {6a 02 59 cd 29 a3 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 66 8c 15 ?? ?? ?? ?? 66 8c 0d ?? ?? ?? ?? 66 8c 1d ?? ?? ?? ?? 66 8c 05 ?? ?? ?? ?? 66 8c 25 ?? ?? ?? ?? 66 8c 2d}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 8d 44 24 ?? 50 6a 00 6a 00 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_SmokeLoader_DX_2147760209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DX!MTB"
        threat_id = "2147760209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 d3 e2 8b c8 c1 e9 ?? 03 4d dc 03 55 e0 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 d1 8b 4d f4 03 c8 33 d1 8b 0d ?? ?? ?? ?? 2b fa 81 f9 ?? ?? ?? ?? 75 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MK_2147766034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MK!MTB"
        threat_id = "2147766034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$URLDOWNLOADER = \"https://paste.ee/r/BjI68\"" ascii //weight: 2
        $x_2_2 = "$DIRECTORY = @TEMPDIR & \"\\HgvQTklIl.ps1\"" ascii //weight: 2
        $x_2_3 = "RUNWAIT ( \"p\" & \"owershell -executionpolicy bypass \" & $DIRECTORY , @SYSTEMDIR , @SW_HIDE )" ascii //weight: 2
        $x_1_4 = "FILEDELETE ( @TEMPDIR & \"\\HgvQTklIl.ps1\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DA_2147768560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DA!MTB"
        threat_id = "2147768560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 44 24 24 8b 44 24 24 89 44 24 20 8b 4c 24 1c 8b 54 24 18 d3 ea 8b cd 8d 44 24 28 89 54 24 28 e8 [0-4] 8b 44 24 20 31 44 24 10 81 3d [0-4] 21 01 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DA_2147768560_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DA!MTB"
        threat_id = "2147768560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 48 02 eb}  //weight: 1, accuracy: High
        $x_1_2 = {83 c1 01 eb}  //weight: 1, accuracy: High
        $x_1_3 = {51 91 59 eb}  //weight: 1, accuracy: High
        $x_1_4 = {b9 ad 2e 00 00 eb}  //weight: 1, accuracy: High
        $x_1_5 = {f7 e1 eb 05}  //weight: 1, accuracy: High
        $x_1_6 = {01 d8 74 07}  //weight: 1, accuracy: High
        $x_1_7 = {89 44 24 fc 83 ec 04 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_HNU_2147809006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.HNU!MTB"
        threat_id = "2147809006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Sosoponazubirin" ascii //weight: 2
        $x_2_2 = "tanugiwecevewupenunikuxagigixizezej" ascii //weight: 2
        $x_2_3 = "keletolazekemamar" ascii //weight: 2
        $x_2_4 = "yuvohiberirosiyucida" ascii //weight: 2
        $x_2_5 = "Cen lumagocatulesak" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPR_2147812792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPR!MTB"
        threat_id = "2147812792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 e8 1f 14 00 00 68 58 14 40 00 6a 00 e8 f3 0f 00 00 6a 00 e8 9c 0f 00 00 6a 00 6a 00 e8 43 0d 00 00 e8 fe 0b 00 00 6a 00 e8 c7 0b 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPF_2147818987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPF!MTB"
        threat_id = "2147818987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be d3 8d 76 01 80 eb 41 8b c2 83 c8 20 80 fb 19 8a 5e ff 0f 47 c2 33 c7 69 f8 93 01 00 01 84 db 75 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DB_2147819552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DB!MTB"
        threat_id = "2147819552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 8b 55 e8 01 10 8b 45 d8 03 45 ac 03 45 e8 8b 55 ec 31 02 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DB_2147819552_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DB!MTB"
        threat_id = "2147819552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cecivirogusuvamigukejoyen" ascii //weight: 2
        $x_2_2 = "lowiwudoyekagiyikuruwu xisigahugopalokig kusahi" ascii //weight: 2
        $x_2_3 = "pisojupesuhezupehesotocunomeguzi" ascii //weight: 2
        $x_2_4 = "culakocijotutuxiniponan raf jazakodub" ascii //weight: 2
        $x_2_5 = "sepukefumenifesaleribehajat pisojupesuhezupehesotocunomeguzi kevatapobaxahiviji" ascii //weight: 2
        $x_1_6 = "Titelanufu mafasereberiyuv riyajexu leduburab faleyatoser" ascii //weight: 1
        $x_1_7 = "C:\\yobuyoticezi\\muv.pdb" ascii //weight: 1
        $x_1_8 = "begoxiraniwoduhibakisasav suluvoyuf hujagohudopilopasom tuyuxatiharovakizirizuvihedom huwizedupusakifayifapagabey" ascii //weight: 1
        $x_1_9 = "pacoletupifodof wotodudokejaxezucudi tazex" ascii //weight: 1
        $x_1_10 = "Guhilituyagorul pajibuzif nene vogorefituyot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SmokeLoader_DC_2147819805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DC!MTB"
        threat_id = "2147819805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 8b 55 e8 01 10 8b 45 d8 03 45 b0 03 45 e8 8b 55 ec 31 02 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DC_2147819805_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DC!MTB"
        threat_id = "2147819805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xolelabapaw suwelicekeziyavijexowihujexet" wide //weight: 1
        $x_1_2 = "covubitupecoziwibuwijidonugawiyocokogatifizifocekikateyibokoyutisurivivow" wide //weight: 1
        $x_1_3 = "vevohidawupujucexekuxulahayozezu jasezawupuniyut" wide //weight: 1
        $x_1_4 = "robumenikihiranotapilujonumupute hehifahavohayuyutibop jehegapowafuwu lotejidamunugulosale guduviyimuwox" wide //weight: 1
        $x_1_5 = "dugalesatefenukacagamogunokuyar jinihic" wide //weight: 1
        $x_1_6 = "cugolorilekuxa wacasogoloh xiwoluwatuvosucupoxihowizab loticenaj" ascii //weight: 1
        $x_1_7 = "zaluloloza\\roba\\jopotih kuxacuza.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DD_2147819979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DD!MTB"
        threat_id = "2147819979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 d8 03 45 ac 03 45 e8 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 89 5d b0 8b 45 ec 8b 55 b0 31 10 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DD_2147819979_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DD!MTB"
        threat_id = "2147819979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xolelabapaw suwelicekeziyavijexowihujexet" wide //weight: 1
        $x_1_2 = "yasegaye jawetew xujofififavujojeyori" wide //weight: 1
        $x_1_3 = "secobawejiwofurobejifijedahidepodizobekubovedabacec" wide //weight: 1
        $x_1_4 = "yojunocaloluvupodezibecohizawih fesoyebitasujimodocedakavar" wide //weight: 1
        $x_1_5 = "Jaj jusazozu wacizijalaci pawizedupebeyarezipumejexumomiv" wide //weight: 1
        $x_1_6 = "vevohidawupujucexekuxulahayozezu jasezawupuniyut" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DE_2147820029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DE!MTB"
        threat_id = "2147820029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 8b 45 b4 8b 55 ec 31 02 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DE_2147820029_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DE!MTB"
        threat_id = "2147820029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 14 89 44 24 20 8b 44 24 28 01 44 24 20 8b 4c 24 1c 8b 54 24 14 d3 ea 8b 4c 24 38 8d 44 24 2c c7 05 [0-4] ee 3d ea f4 89 54 24 2c e8 [0-4] 8b 44 24 20 31 44 24 10 81 3d [0-4] e6 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_XV_2147820119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.XV!MTB"
        threat_id = "2147820119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 ec 89 45 f0 8b 45 e4 8b 4d e8 d3 e8 89 45 f8 8b 45 cc 01 45 f8 8b 7d e4 c1 e7 04 03 7d d8 33 7d f0 81 3d e4 ba 8e 00 ?? ?? ?? ?? 75 09 56 56 56 ff 15 ?? ?? ?? ?? 33 7d f8 89 35 ?? ?? ?? ?? 89 7d c8 8b 45 c8 29 45 f4 8b 45 dc 29 45 fc ff 4d e0 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DF_2147820130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DF!MTB"
        threat_id = "2147820130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 ?? ?? ?? ?? 8b d8 03 5d b4 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DF_2147820130_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DF!MTB"
        threat_id = "2147820130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fowopukexorehobejirirawupenu sesarezopocovavigowuwafeyey" wide //weight: 1
        $x_1_2 = "nakobepepuwisojofujalexe" wide //weight: 1
        $x_1_3 = "vujoniyayetikowezawiru kihojecagojuhosajanirosu" wide //weight: 1
        $x_1_4 = "gijocujuvepo nenopufelasawimuwisuwebox" wide //weight: 1
        $x_1_5 = "nikewasecitigofaricoxemusipewip gumipitifirikoxanisabagi" ascii //weight: 1
        $x_1_6 = "dureracobanokituwu tuwehajapug jujaxazubuweceset petecifoduvikilabonoralezobu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DG_2147824680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DG!MTB"
        threat_id = "2147824680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DG_2147824680_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DG!MTB"
        threat_id = "2147824680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 0c 37 89 4c 24 20 8b 4c 24 1c 8b d6 d3 ea 8b 4c 24 38 8d 44 24 14 c7 05 [0-4] ee 3d ea f4 89 54 24 14 e8 [0-4] 8b 44 24 20 31 44 24 10 81 3d [0-4] e6 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_NE_2147824718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.NE!MTB"
        threat_id = "2147824718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 0c 8b c6 c1 e8 05 89 45 08 8b 45 ec 01 45 08 8b 45 e8 83 25 ?? ?? ?? ?? ?? 03 f8 33 7d 08 33 7d 0c 89 7d 08 8b 45 08 01 05 ?? ?? ?? ?? 8b 45 08 29 45 fc 8b 4d fc c1 e1 04 03 4d f0 8b 45 fc 03 45 f8 89 45 0c 8b 55 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_D_2147829816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.D!MTB"
        threat_id = "2147829816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 ff 8b 45 08 0f be 14 10 69 d2}  //weight: 2, accuracy: High
        $x_2_2 = {03 ce 8b 45 0c 03 45 ?? 88 08 0f be 4d ?? 8b 55 0c 03 55 ?? 0f b6 02 2b c1 8b 4d 0c 03 4d ?? 88 01 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_D_2147829816_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.D!MTB"
        threat_id = "2147829816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 84 38 4b 13 01 00 8b 0d ?? ?? ?? ?? 88 04 39 75 06 ff 15 ?? ?? ?? ?? 47 3b 3d ?? ?? ?? ?? 72 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ef 89 45 e0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d e4 8b 45 e0 31 45 fc 33 7d fc}  //weight: 1, accuracy: Low
        $x_1_3 = {31 7d fc 8b 45 fc 29 45 f4 81 c3 47 86 c8 61 ff 4d e8 0f 85 ?? fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_D_2147829816_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.D!MTB"
        threat_id = "2147829816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ca 8b c2 c1 e8 05 c1 e1 04 03 4d ec 03 c3 33 c1 33 45 fc 89 45 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 c7}  //weight: 10, accuracy: Low
        $x_10_2 = {55 8b ec 51 56 be ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_E_2147829905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.E!MTB"
        threat_id = "2147829905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 0c 24 b8 d1 05 00 00 01 04 24 8b 14 24 8a 04 32 8b 0d ?? ?? ?? ?? 88 04 31 81 c4 04 08 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_E_2147829905_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.E!MTB"
        threat_id = "2147829905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c7 33 c1 8b ca c1 e9 ?? 03 4d f0 89 45 08 33 c8 89 4d 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 fc 8b 45 fc c1 e0 ?? 89 45 08}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 73 58 6a 6d 66 a3 ?? ?? ?? ?? 58 6a 67 66 a3 ?? ?? ?? ?? 58 6a 69 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_N_2147830625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.N!MTB"
        threat_id = "2147830625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 8d 04 13 d3 ea 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 d8 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ec 75 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_R_2147830854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.R!MTB"
        threat_id = "2147830854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 4c 24 0c 30 04 31 46 3b f7 7c d0}  //weight: 4, accuracy: High
        $x_1_2 = "tugoxupijebuvizanigijevawixolutu" ascii //weight: 1
        $x_1_3 = "ximawazudikahefafopoporifozib kadamuzayecep hizujajugejusawaharidam wunoguzazapeguvecazageganuzi" ascii //weight: 1
        $x_1_4 = "ninucetuwodizatabisihayacix" ascii //weight: 1
        $x_1_5 = "hovocafisavexujegiselano" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SmokeLoader_RPA_2147831134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPA!MTB"
        threat_id = "2147831134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 ba 00 00 00 00 f7 75 14 8b 45 08 01 d0 0f b6 00 ba 7c 00 00 00 0f af c2 31 c1 8b 55 f4 8b 45 0c 01 d0 89 ca 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_B_2147831165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.B!MTB"
        threat_id = "2147831165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 e8 03 c3 33 c2 31 45 fc 2b 75 fc 8b 45 d4 29 45 f8 ff 4d e8 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_A_2147831528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.A!MTB"
        threat_id = "2147831528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "94"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "System.Net.WebProxy" wide //weight: 10
        $x_10_2 = "WebRequestSession" wide //weight: 10
        $x_10_3 = "http" wide //weight: 10
        $x_10_4 = "Get-RegistryValue" wide //weight: 10
        $x_10_5 = "while ($" wide //weight: 10
        $x_10_6 = ".StartsWith(" wide //weight: 10
        $x_10_7 = "[System.Text.Encoding]::UTF8.GetString($" wide //weight: 10
        $x_10_8 = "Byte[]" wide //weight: 10
        $x_10_9 = ".content" wide //weight: 10
        $x_3_10 = "iwr " wide //weight: 3
        $x_3_11 = "invoke-webrequest" wide //weight: 3
        $x_1_12 = "invoke-expression $" wide //weight: 1
        $x_1_13 = "iex $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((9 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SmokeLoader_A_2147831528_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.A!MTB"
        threat_id = "2147831528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 44 24 24 8b 44 24 24 89 44 24 20 8b 54 24 18 8b 4c 24 1c d3 ea 89 54 24 14 8b 44 24 34 01 44 24 14 8b 44 24 20 31 44 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_A_2147831528_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.A!MTB"
        threat_id = "2147831528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 dc 01 45 fc 8b 55 f8 8b 4d f4 8b c2 d3 e8 8d 34 17 81 c7 47 86 c8 61 03 45 e4 33 c6 31 45 fc 2b 5d fc ff 4d ec 0f 85 01 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_A_2147831528_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.A!MTB"
        threat_id = "2147831528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "midezoyobugalodolobuvelelezocokakufofafaca" ascii //weight: 1
        $x_1_2 = "segopezehuyorosece" ascii //weight: 1
        $x_1_3 = "kkurikolisidudiguyik" ascii //weight: 1
        $x_1_4 = "Solofudi goxoruv sapocuzi" ascii //weight: 1
        $x_1_5 = "alloca was corrupted" ascii //weight: 1
        $x_1_6 = "f:\\dd\\vct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_FRX_2147831557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.FRX!MTB"
        threat_id = "2147831557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7d 1b 75 77 6b c6 25 b5 ad 1b 73 22 f4 82 29 a1 5c f2 2b 20 3b 58 48 75 b9 f4 d4 12 b2 6b db 44 52 e6 61 c0 43 fe 6a 7f ae 2f ef 7b 7d 43 16 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPJ_2147831760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPJ!MTB"
        threat_id = "2147831760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 28 8b d0 d3 e2 8b 4c 24 10 03 c8 c1 e8 05 03 d5 89 54 24 14 89 4c 24 1c 89 44 24 18 8b 44 24 3c 01 44 24 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GXW_2147832355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GXW!MTB"
        threat_id = "2147832355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 f0 8b 4d f4 c1 e9 05 89 4d ec 8b 45 d4 01 45 ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 e4 33 45 ec 89 45 e4 c7 05 ?? ?? ?? ?? 00 00 00 00 8b 4d d0 2b 4d e4 89 4d d0 8b 45 d8 29 45 e8 e9 02 fb ff ff}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GTB_2147832469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GTB!MTB"
        threat_id = "2147832469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d ec 8b c3 d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 c4 89 45 f4 8b 45 e8 31 45 fc 8b 45 fc 31 45 f4 83 3d ?? ?? ?? ?? 0c 75}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GTE_2147832646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GTE!MTB"
        threat_id = "2147832646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c2 c1 e8 ?? 03 45 ec 68 ?? ?? ?? ?? 33 45 0c c7 05 ?? ?? ?? ?? 19 36 6b ff 33 c7 2b d8}  //weight: 10, accuracy: Low
        $x_10_2 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 c2 08 00 55 8b ec 8b 4d 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GTH_2147832724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GTH!MTB"
        threat_id = "2147832724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 c1 e8 05 03 45 e4 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 45 0c 33 c7 2b d8 ff 4d f0}  //weight: 10, accuracy: Low
        $x_10_2 = {ec 8d 0c 07 33 4d 0c 89 35 ?? ?? ?? ?? 33 4d f4 89 4d f4 8b 45 f4 01 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GTI_2147832805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GTI!MTB"
        threat_id = "2147832805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 0c 03 33 4d 0c 89 35 ?? ?? ?? ?? 33 cf 89 4d f0 8b 45}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c3 c1 e8 ?? 03 45 e0 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 45 0c 33 f8 89 7d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MA_2147832891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MA!MTB"
        threat_id = "2147832891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 ff 8b d0 c1 ea 05 03 54 24 30 8b c8 c1 e1 04 89 54 24 1c 03 cd 8d 14 06 33 ca 89 4c 24 10 89 3d 68 73 7b 00 8b 44 24 1c 01 05 68 73 7b 00}  //weight: 5, accuracy: High
        $x_5_2 = {8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 4c 24 1c 89 4c 24 1c 8b 44 24 1c 29 44 24 14 8b 4c 24 14 8b c1 c1 e0 04 03 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MA_2147832891_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MA!MTB"
        threat_id = "2147832891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 7d f4 8b c7 c1 e0 04 03 45 e0 89 45 f8 8b 45 f4 03 45 f0 89 45 0c ff 75 0c 83 0d ?? ?? ?? ?? ff 8b d7 8d 45 f8 c1 ea 05 03 55 e8 50 c7 05}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 73 58 6a 6d 66 a3 ?? ?? ?? ?? 58 6a 67 66 a3 ?? ?? ?? ?? 58 6a 69 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 6a 32 66 a3 ?? ?? ?? ?? 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GTL_2147832944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GTL!MTB"
        threat_id = "2147832944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 45 e0 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 45 0c 33 f8 89 7d f8 8b 45 f8 29 45 fc 81 45 ?? 47 86 c8 61 ff 4d ec}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 0c 33 45 10 8b 4d 08 89 01 5d c2 0c 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GTO_2147833007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GTO!MTB"
        threat_id = "2147833007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 c1 e8 05 03 45 e0 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 45 ?? 33 f8 89 7d f4 8b 45 f4 29 45 fc 89 75 f8 8b 45 d8 01 45 f8 2b 5d f8 ff 4d ec 89 5d e8 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_FRY_2147833247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.FRY!MTB"
        threat_id = "2147833247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 c1 e8 05 03 45 e0 03 fa 33 f8 33 7d 0c}  //weight: 1, accuracy: High
        $x_1_2 = {89 7d f0 8b 45 f0 29 45 fc 89 75 f8 8b 45 e4 01 45 f8 2b 5d f8 ff 4d e8 89 5d f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_FRS_2147833313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.FRS!MTB"
        threat_id = "2147833313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 37 1c 8b 45 fc 0f b7 00 8d 04 81 8b 3c 30 83 65 e4 00 8d 45 d8 50 03 fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_FRP_2147833314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.FRP!MTB"
        threat_id = "2147833314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 3e 50 31 50 23 50 50 50 08 d9 16 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GTZ_2147833336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GTZ!MTB"
        threat_id = "2147833336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d7 d3 e2 8b 4d ec 89 45 f0 8b c7 03 55 d8 d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 45 f8 33 45 f0 89 35 ?? ?? ?? ?? 33 d0 29 55 e4 8b 45 cc 29 45 f4 ff 4d e0 0f 85}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GI_2147833598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GI!MTB"
        threat_id = "2147833598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c3 c1 e8 05 03 45 e0 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ec 8b 45 f8 31 45 0c 8b 45 ec 31 45 0c 8b 45 0c 29 45 fc 89 75 f4 8b 45 d0 01 45 f4 2b 7d f4 ff 4d e4 8b 4d fc 89 7d e8 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GJP_2147833944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GJP!MTB"
        threat_id = "2147833944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e0 03 45 dc 33 45 ec 33 c2 89 45 ec 8b 45 ec 29 45 fc 81 45 ?? 47 86 c8 61 ff 4d e4 0f 85}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_FXU_2147834139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.FXU!MTB"
        threat_id = "2147834139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 84 30 3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? 92 02 00 00 75 16 68 ?? ?? ?? ?? 53 53 ff 15 ?? ?? ?? ?? 53 53 53 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GJQ_2147834158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GJQ!MTB"
        threat_id = "2147834158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d3 e2 89 35 ?? ?? ?? ?? 03 55 d0 33 55 e8 33 d7 89 55 e8 8b 45 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {d3 e8 8b 4d dc c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 e8 8d 45 e8 e8 ?? ?? ?? ?? 33 7d f0 31 7d e8 83 3d ?? ?? ?? ?? 1f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GJV_2147834282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GJV!MTB"
        threat_id = "2147834282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c6 d3 ee 8b 4c 24 ?? 89 44 24 ?? 8d 44 24 ?? 89 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GJV_2147834282_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GJV!MTB"
        threat_id = "2147834282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d3 ea 8b 4d cc 8d 45 e4 89 5d f4 89 55 e4 e8 ?? ?? ?? ?? 8b 45 e4 33 c3 31 45 e0 89 35 ?? ?? ?? ?? 8b 45 e0 29 45 fc 81 45 ?? 47 86 c8 61 ff 4d dc 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_JER_2147834498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.JER!MTB"
        threat_id = "2147834498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 83 3d ?? ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 8b 4d ?? 89 45 e8 8d 45 e8 e8 ?? ?? ?? ?? 8b 45 e8 33 c3 31 45 f8 89 35 ?? ?? ?? ?? 8b 45 f4 89 45 e0 8b 45 f8 29 45 e0 8b 45 e0 89 45 f4 81 45 e4 ?? ?? ?? ?? ff 4d d8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BS_2147834527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BS!MTB"
        threat_id = "2147834527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 ea 8b 4d c4 8d 45 e0 89 55 e0 e8 [0-4] 8b 45 e0 33 c3 31 45 f8 89 35 [0-4] 8b 45 f4 89 45 e4 8b 45 f8 29 45 e4 8b 45 e4 89 45 f4 81 45 dc 47 86 c8 61 ff 4d d8 0f}  //weight: 2, accuracy: Low
        $x_2_2 = {81 00 e1 34 ef c6 c3 01 08 c3 01 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_HEQ_2147834591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.HEQ!MTB"
        threat_id = "2147834591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 83 3d ?? ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 c3 31 45 ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 89 45 e4 8b 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_SA_2147834596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.SA!MTB"
        threat_id = "2147834596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 c3 31 45 ?? 89 35 ?? ?? ?? ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GTA_2147834648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GTA!MTB"
        threat_id = "2147834648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 e4 8d 45 e4 e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 8b 7d ?? 33 7d ?? 83 3d ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 e4 33 c7 31 45 fc 89 35 ?? ?? ?? ?? 8b 45 f4 89 45 e8 8b 45 fc 29 45 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BJ_2147834673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BJ!MTB"
        threat_id = "2147834673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e8 8b 4d c8 89 45 e0 8d 45 e0 e8 [0-4] 8b 45 e0 33 c7 31 45 f8 89 35 [0-4] 8b 45 f0 89 45 e4 8b 45 f8 29 45 e4 8b 45 e4 89 45 f0 8b 45 c0 29 45 f4 ff 4d d8 0f}  //weight: 2, accuracy: Low
        $x_2_2 = {81 00 e1 34 ef c6 c3 29 08 c3 01 08 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ARA_2147835015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ARA!MTB"
        threat_id = "2147835015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 8c 30 4b 13 01 00 a1 ?? ?? ?? ?? 88 0c 30 81 fa ?? ?? ?? ?? 75 3a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ARA_2147835015_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ARA!MTB"
        threat_id = "2147835015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a1 10 c9 83 00 8a 84 38 3b 2d 0b 00 8b 0d 08 bf 83 00 88 04 39 81 3d 0c c9 83 00 92 02 00 00 75 0d 68 54 2e 40 00 56 56 ff 15 7c 10 40 00 47 3b 3d 0c c9 83 00 72 c9}  //weight: 2, accuracy: High
        $x_2_2 = "pagehokizalobusebiyux" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_FV_2147835069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.FV!MTB"
        threat_id = "2147835069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 33 f6 56 8d 45 ?? 50 56 8d 85 ?? ?? ?? ?? 50 56 56 68 e0 12 40}  //weight: 1, accuracy: Low
        $x_1_2 = {50 8d 45 fc 50 8d 45 e4 50 8d 45 ec 50 8d 45 f4 50 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_FT_2147835070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.FT!MTB"
        threat_id = "2147835070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 45 0c 53 56 8b 75 08 03 c6 89 45 08 8b 45 14 33 db 89 18 8a 16 8b 45 10 57 8b ce 80 fa 11}  //weight: 1, accuracy: High
        $x_1_2 = {8a 11 88 10 40 41 4f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BK_2147835111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BK!MTB"
        threat_id = "2147835111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e8 05 03 45 ec 03 f2 33 c6 33 45 fc c7 05 [0-4] 19 36 6b ff 89 45 f4 8b 45 f4 29 45 08 83 65 0c 00 8b 45 dc 01 45 0c 2b 7d 0c ff 4d f0 8b 45 08 89 7d f4 0f}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 0c 07 8b d0 c1 ea 05 03 55 e8 c1 e0 04 03 45 e0 89 4d fc 33 d0 33 d1 52}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MIV_2147835237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MIV!MTB"
        threat_id = "2147835237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 fc 8b 45 fc 31 45 f8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ea 89 55 f8 8b 45 ?? 01 45 f8 8b 45 f8 33 c7 31 45 fc 89 35 ?? ?? ?? ?? 8b 45 f4 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_IPH_2147835337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.IPH!MTB"
        threat_id = "2147835337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 c1 e1 04 03 4d d8 89 4d f8 8b 0d}  //weight: 1, accuracy: High
        $x_1_2 = {8b c2 d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 c7 31 45 f8 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 81 c3 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_SP_2147835406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.SP!MTB"
        threat_id = "2147835406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 c4 18 31 c0 5b c3 8d 76 00 c7 44 24 04 ff ff ff ff 8b 43 04 89 04 24 ff 15 d4 b1 42 00 83 ec 08 85 c0 74 db}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BL_2147835492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BL!MTB"
        threat_id = "2147835492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f8 03 c1 89 45 0c 8b c1 c1 e8 05 89 45 08 8b 45 e8 01 45 08 c1 e1 04 03 4d ec 8d 45 fc 33 4d 08 33 d2 33 4d 0c 89 15 [0-4] 51 50 89 4d 08}  //weight: 2, accuracy: Low
        $x_2_2 = {c1 e8 05 c7 05 [0-4] 19 36 6b ff 89 45 08 8b 45 e4 01 45 08 03 f3 33 75 08 8d 45 f4 33 75 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_TON_2147835499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.TON!MTB"
        threat_id = "2147835499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 89 45 ?? 8b c2 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 8b c2}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 fc 33 45 ?? 31 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RE_2147835533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RE!MTB"
        threat_id = "2147835533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ab 0f 1b 81 6c 24 ?? 8d 1f 25 59 81 ac 24 ?? 00 00 00 e0 02 53 2c 81 ?? 24 [0-4] f0 b0 7d 6d 81 84 24 ?? 00 00 00 40 c1 58 20 81 44 24 ?? f0 98 30 35 b8 8c 6d 49 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RE_2147835533_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RE!MTB"
        threat_id = "2147835533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 e1 34 ef c6 c3 29 08 c3 01 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 55 ?? 8b 4d ?? 8b c2 d3 e0 [0-64] 8b c2 d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 45 ?? 31 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AD_2147835566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AD!MTB"
        threat_id = "2147835566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {89 7c 24 fc 83 ec 04 56 ba ?? ?? ?? ?? e8 00 00 00 00 5e 81 ee ?? ?? ?? ?? 01 c6 89 f7}  //weight: 100, accuracy: Low
        $x_100_3 = {8b 34 24 83 c4 04 81 ee ?? ?? ?? ?? 01 c6}  //weight: 100, accuracy: Low
        $x_100_4 = {30 d0 aa e2 ?? 75 0a 00 30 d0 aa ac 30 d0}  //weight: 100, accuracy: Low
        $x_100_5 = {e8 00 00 00 00 83 c4 04 8b 74 24 fc 81 ee ?? ?? ?? ?? 01 c6 89 f7}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SmokeLoader_BM_2147835575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BM!MTB"
        threat_id = "2147835575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f8 8b 4d f0 8d 3c 10 8b c2 d3 e8 89 7d e8 89 35 [0-4] 03 45 c8 33 c7 31 45 fc 8b 45 f4 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f4 8b 45 c4 29 45 f8 ff 4d d8 0f}  //weight: 2, accuracy: Low
        $x_2_2 = {81 00 e1 34 ef c6 c3 29 08 c3 01 08 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_OGG_2147835720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.OGG!MTB"
        threat_id = "2147835720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 55 ?? 89 3d ?? ?? ?? ?? 03 45 ?? 33 c2 31 45 fc 8b 45 ?? 89 45 e4 8b 45 fc 29 45 ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_NEAB_2147835725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.NEAB!MTB"
        threat_id = "2147835725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 f4 8b c8 03 d0 c1 e1 04 03 4d e8 c1 e8 05 89 55 0c 89 45 08 8b 45 e4 01 45 08 8b 45 08 33 45 0c 33 d2 33 c1 50 89 45 08 8d 45 f8 50}  //weight: 10, accuracy: High
        $x_10_2 = {89 45 08 8b 45 ec 01 45 08 03 f3 33 75 08 33 75 0c 89 75 e0 8b 45 e0 29 45 fc 81 45 f4 ?? ?? ?? ?? ff 4d f0 8b 45 fc 0f 85 ?? ?? ?? ?? 89 07 89 4f 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ONG_2147835769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ONG!MTB"
        threat_id = "2147835769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ea 03 c7 89 45 ?? 03 55 ?? 8b 45 ?? 31 45 ?? 31 55 ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 89 45 e4 8b 45 ?? 29 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RTT_2147835779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RTT!MTB"
        threat_id = "2147835779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? c1 e1 04 03 4d ?? 8d 45 ?? 33 4d ?? 33 d2 33 4d ?? 89 15}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 08 8b 45 ?? 03 f0 33 75 ?? 8d 45 ?? 33 75 ?? 56 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AL_2147835803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AL!MTB"
        threat_id = "2147835803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 03 c6 89 45 e8 03 55 cc 8b 45 e8 31 45 fc 31 55 fc 89 3d ?? ?? ?? ?? 8b 45 f4 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f4 8b 45 c8 29 45 f8 ff 4d dc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CME_2147835860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CME!MTB"
        threat_id = "2147835860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 4d ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 33 45 ?? 50}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? ff 75 ?? 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MF_2147836049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MF!MTB"
        threat_id = "2147836049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? ff 75 ?? 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MZS_2147836078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MZS!MTB"
        threat_id = "2147836078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 03 45 ?? 89 45 ?? 8b 45 ?? 03 55 ?? 03 c7 89 45 ?? 8b 45 ?? 31 45 ?? 31 55 ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_WAS_2147836237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.WAS!MTB"
        threat_id = "2147836237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? ff 75 ?? 03 f3 33 75 ?? 8d 45 ?? 50 89 75 ?? e8 ?? ?? ?? ?? ff 75 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 81 45 f8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MP_2147836290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MP!MTB"
        threat_id = "2147836290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c 90 01 45 08 8b 45 08 89 01 5d c2 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MPA_2147836327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MPA!MTB"
        threat_id = "2147836327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 08 8b 45 e8 01 45 08 ff 75 08 8b c3 c1 e0 04 03 c6 33 45 0c 89 45 0c 8d 45 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_HR_2147836417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.HR!MTB"
        threat_id = "2147836417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 03 cb 33 4d ?? 33 4d ?? 2b f1 89 4d ?? 89 75 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? ff 75 ?? 8b c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_WW_2147836446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.WW!MTB"
        threat_id = "2147836446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 03 45 ?? 89 45 ?? 8b 45 ?? 03 55 ?? 03 c7 89 45 ?? 8b 45 ?? 31 45 ?? 31 55 ?? 8b 45 ?? 29 45 ?? 81 45 ec ?? ?? ?? ?? ff 4d ?? 89 35 ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GBC_2147836500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GBC!MTB"
        threat_id = "2147836500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e0 8b 4d ?? 8b d6 d3 ea 03 45 ?? 89 45 ?? 8b 45 ?? 03 55 ?? 03 c6 89 45 ?? 8b 45 ?? 31 45 ?? 31 55 ?? 89 3d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_JK_2147836598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.JK!MTB"
        threat_id = "2147836598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 03 45 ?? 33 45 ?? 89 45 ?? 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 45 ?? 8b 4d ?? 31 08 5d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_HGK_2147836633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.HGK!MTB"
        threat_id = "2147836633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 3d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 81 45 e4 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GBH_2147836713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GBH!MTB"
        threat_id = "2147836713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e0 8b 4d ?? 03 45 ?? 89 45 ?? 8b 45 ?? 03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 3d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GBL_2147836874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GBL!MTB"
        threat_id = "2147836874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b f0 8b c6 c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 01 45 ?? 8b c6 c1 e0 ?? 03 45 ?? 8d 0c 32 33 c1 33 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74 ?? 81 c2 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MI_2147837061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MI!MTB"
        threat_id = "2147837061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b c6 c1 e0 ?? 03 45 ?? 8d 0c 33 33 c1 33 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GBQ_2147837119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GBQ!MTB"
        threat_id = "2147837119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 ff d5 e8 ?? ?? ?? ?? 8b 4c 24 0c 30 04 31 46 3b f7 7c}  //weight: 10, accuracy: Low
        $x_10_2 = {b1 6c b0 6d 68 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 67 88 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_KWL_2147837144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.KWL!MTB"
        threat_id = "2147837144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e0 ?? 03 45 ?? 03 de 33 c3 33 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GBS_2147837191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GBS!MTB"
        threat_id = "2147837191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b f8 8b c7 c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 01 45 ?? 8b c7 c1 e0 04 03 45 ?? 8d 0c 3e 33 c1 33 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 83 65 ?? ?? 8b 45 ?? 01 45 ?? 2b 75 ?? ff 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_KX_2147837205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.KX!MTB"
        threat_id = "2147837205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 8b 4d ?? 8b de d3 e3 03 45 ?? 89 55 ?? 89 45 ?? 03 5d ?? 33 d8 33 da 89 5d ?? 33 db 89 1d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 81 45 ?? ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_KZ_2147837258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.KZ!MTB"
        threat_id = "2147837258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 ea 8b 4d ?? 8b c6 d3 e0 03 55 ?? 89 7d ?? 89 55 ?? 03 45 ?? 33 c2 33 c7 29 45 ?? ff 4d ?? 89 45 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_FIF_2147837403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.FIF!MTB"
        threat_id = "2147837403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 65 ?? ?? 8b c6 c1 e0 ?? 03 45 ?? 33 45 ?? 33 c1 2b f8 8b 45 ?? 01 45 ?? 29 45 ?? 4a 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BO_2147837488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BO!MTB"
        threat_id = "2147837488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e0 8b 4d f0 03 45 d4 89 45 f8 8b 45 e8 03 c6 89 45 f4 8b c6 d3 e8 03 45 d0 89 45 fc 8b 45 f4 31 45 f8 8b 45 f8 33 45 fc 83 25 [0-4] 00 81 45 e8 47 86 c8 61 2b d8 ff 4d e0 89 45 f8 89 5d e4 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_KL_2147837489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.KL!MTB"
        threat_id = "2147837489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 e8 03 45 d0 89 45 fc 8b 45 f4 31 45 f8 8b 45 f8 33 45 fc 83 25 0c e7 42 00 00 81 45 e8 47 86 c8 61 2b d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_FIZ_2147837521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.FIZ!MTB"
        threat_id = "2147837521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 8b c6 c1 e0 ?? 03 45 ?? 03 ce 33 c1 33 45 ?? 68 ?? ?? ?? ?? 2b f8 8d 45 ?? 50 e8 ?? ?? ?? ?? 4a 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_IM_2147837654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.IM!MTB"
        threat_id = "2147837654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 8b c6 c1 e0 ?? 03 45 ?? 03 ce 33 c1 33 45 ?? 68 ?? ?? ?? ?? 2b f8 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_IJ_2147837664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.IJ!MTB"
        threat_id = "2147837664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 2b d8 89 45 ?? 89 5d ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BP_2147837696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BP!MTB"
        threat_id = "2147837696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e0 8b 4d ec 03 45 d4 89 45 f4 8b 45 fc 03 c6 89 45 f0 8b c6 d3 e8 03 45 d0 89 45 f8 8b 45 f0 31 45 f4 8b 45 f4 33 45 f8 89 1d [0-4] 29 45 e4 89 45 f4 8b 45 cc 29 45 fc ff 4d e0 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_IW_2147837810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.IW!MTB"
        threat_id = "2147837810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 65 ?? ?? 8b c6 c1 e0 ?? 03 45 ?? 33 45 ?? 33 c1 2b f8 8b 45 ?? 01 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDB_2147837814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDB!MTB"
        threat_id = "2147837814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c6 89 45 f0 8b c6 d3 e8 03 45 d0 89 45 f8 8b 45 f0 31 45 f4 8b 45 f4 33 45 f8 89 1d ?? ?? ?? ?? 29 45 e4 89 45 f4 8b 45 cc 29 45 fc}  //weight: 2, accuracy: Low
        $x_1_2 = "kernel32.dll" ascii //weight: 1
        $x_1_3 = "LocalAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_XI_2147837860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.XI!MTB"
        threat_id = "2147837860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 81 45 ?? ?? ?? ?? ?? 8b c6 c1 e0 ?? 03 45 ?? 03 ce 33 c1 33 45 ?? 2b f8 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_XL_2147837878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.XL!MTB"
        threat_id = "2147837878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 2b d8 ff 4d ?? 89 45 ?? 89 5d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_IT_2147837949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.IT!MTB"
        threat_id = "2147837949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 8b c6 c1 e0 ?? 03 45 ?? 03 ce 33 c1 33 45 ?? 2b f8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GCG_2147838005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GCG!MTB"
        threat_id = "2147838005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 89 45 08 8d 45 08 50 c7 05 ?? ?? ?? ?? 19 36 6b ff e8 ?? ?? ?? ?? 8b 4d ?? 8b c6 c1 e0 ?? 03 45 e8 03 ce 33 c1 33 45 08 2b f8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74 ?? 81 45 ?? 47 86 c8 61 ff 4d f8 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GCJ_2147838065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GCJ!MTB"
        threat_id = "2147838065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e0 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 4d ?? 03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 1d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BQ_2147838107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BQ!MTB"
        threat_id = "2147838107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f0 8b c6 c1 e8 05 89 45 08 8d 45 08 50 c7 05 [0-4] 19 36 6b ff e8 [0-4] 8b 4d fc 8b c6 c1 e0 04 03 45 e8 03 ce 33 c1 33 45 08 2b f8 81 3d [0-4] 93 00 00 00 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BR_2147838122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BR!MTB"
        threat_id = "2147838122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f0 8b 45 fc 8d 14 30 8b c6 c1 e8 05 89 45 08 8d 45 08 50 c7 05 [0-4] 19 36 6b ff e8 [0-4] 83 65 0c 00 8b c6 c1 e0 04 03 45 e4 33 45 08 33 c2 2b f8 8b 45 e0 01 45 0c 29 45 fc ff 4d f4 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_XY_2147838163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.XY!MTB"
        threat_id = "2147838163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3e 87 e1 15 ?? ?? ?? ?? 0d ?? ?? ?? ?? b4 ?? 31 31 31 f9 0d ?? ?? ?? ?? 35 ?? ?? ?? ?? 9c}  //weight: 1, accuracy: Low
        $x_1_2 = {49 28 a0 44 ?? ?? ?? 11 d9 67 31 31 31 da 39 9d ?? ?? ?? ?? 11 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_FR_2147838230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.FR!MTB"
        threat_id = "2147838230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? 51 8d 45 ?? 50 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
        $x_1_2 = "feyicujey-mividefefute-jasi92_domu.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GCP_2147838244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GCP!MTB"
        threat_id = "2147838244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e8 ?? 89 45 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 52 8d 45 ?? 50 e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 83 65 ?? ?? 2b f0 8b 45 ?? 01 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_IE_2147838249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.IE!MTB"
        threat_id = "2147838249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 1d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 81 45 ?? ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_IZ_2147838250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.IZ!MTB"
        threat_id = "2147838250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 65 60 8b 45 ?? 81 6d ?? ?? ?? ?? ?? 81 6d ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 81 6d ?? ?? ?? ?? ?? 8b 45 ?? 8b 4d ?? 31 08 83 c5}  //weight: 1, accuracy: Low
        $x_1_2 = {52 8d 45 0c 50 e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 83 65 ?? ?? 2b f0 8b 45 ?? 01 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BT_2147838292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BT!MTB"
        threat_id = "2147838292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e0 89 45 fc 8b 45 d4 01 45 fc 8b 45 f8 8b 4d ec 03 c6 89 45 e4 8b c6 d3 e8 03 45 d0 89 45 f4 8b 45 e4 31 45 fc 8b 45 f4 31 45 fc 89 1d [0-4] 8b 45 fc 29 45 f0 8b 45 cc 29 45 f8 ff 4d e0 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MIU_2147838372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MIU!MTB"
        threat_id = "2147838372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 89 45 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 52 8d 45 ?? 50 e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 83 65 ?? ?? 2b f8 8b 45 ?? 01 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GCT_2147838398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GCT!MTB"
        threat_id = "2147838398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 14 30 8b c6 c1 e8 05 89 45 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 52 8d 45 ?? 50 e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 2b f8 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BU_2147838423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BU!MTB"
        threat_id = "2147838423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 45 ec 8b 45 ec 89 45 e4 8b 4d f0 8b c3 d3 e8 03 45 c8 89 45 f8 8b 45 e4 31 45 fc 8b 45 f8 31 45 fc 89 35 [0-4] 8b 45 fc 29 45 f4 8d 45 e0 e8 [0-4] ff 4d dc 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BV_2147838477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BV!MTB"
        threat_id = "2147838477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 45 f0 8b 45 f0 89 45 e8 8b 4d f4 8b c7 d3 e8 03 45 c8 89 45 f8 8b 45 e8 31 45 fc 8b 45 fc 33 45 f8 89 1d [0-4] 29 45 e0 89 45 fc 8d 45 e4 e8 [0-4] ff 4d dc 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_XZ_2147838546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.XZ!MTB"
        threat_id = "2147838546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a 39 39 c6 6a ?? b4 ?? c5 69 ?? 4c 29 c6 4c 35 ?? ?? ?? ?? c6 c6 ?? f9 4d 34 ?? 4c 2d ?? ?? ?? ?? 6a}  //weight: 1, accuracy: Low
        $x_1_2 = {33 31 b8 d7 ?? ?? ?? 39 d2 3c ?? d2 cc 31 11 d2 3c 39 0b 55 ?? d4 ?? ff 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RR_2147838547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RR!MTB"
        threat_id = "2147838547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 2b d8 89 45 ?? 8d 45 ?? 89 5d ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MJO_2147838676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MJO!MTB"
        threat_id = "2147838676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e0 ?? 03 45 ?? 8d 0c 33 33 c1 33 45 ?? 81 c3 ?? ?? ?? ?? 2b f8 ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CB_2147838698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CB!MTB"
        threat_id = "2147838698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 78 8b 4d 7c 31 08 83 c5 70 c9 c2 08 00 55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c 01 45 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CB_2147838698_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CB!MTB"
        threat_id = "2147838698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 7c 24 10 89 6c 24 24 8b 44 24 2c 01 44 24 24 8b 44 24 3c 90 01 44 24 24 8b 44 24 24 89 44 24 1c}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4c 24 20 8b c6 d3 e8 8b 4c 24 1c 31 4c 24 10 03 c3 81 3d [0-4] 21 01 00 00 89 44 24 14 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_QQ_2147838791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.QQ!MTB"
        threat_id = "2147838791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 89 45 ?? 8d 45 ?? 50 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 04 33 33 45 ?? 81 c3 ?? ?? ?? ?? 31 45 ?? 2b 7d ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BWM_2147838863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BWM!MTB"
        threat_id = "2147838863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 81 45 e0 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_UY_2147838881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.UY!MTB"
        threat_id = "2147838881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ae 00 c6 c6 c6 ?? 2d ?? ?? ?? ?? 32 d7 2e 20 38 39 39 5f 28 00 e5 ?? a2 ?? ?? ?? ?? 02 c2 2d ?? ?? ?? ?? 34 ?? 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GDC_2147838889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GDC!MTB"
        threat_id = "2147838889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 d3 e0 89 45 ?? 8b 45 ?? 01 45 ?? 89 75 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? ?? 01 45 ?? 8b 45 ?? 89 45 ?? 8b 4d ?? 8b c7 d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_KI_2147838906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.KI!MTB"
        threat_id = "2147838906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BW_2147838950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BW!MTB"
        threat_id = "2147838950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e8 05 03 45 e8 c7 05 [0-4] 19 36 6b ff 89 45 0c 8b 45 fc 03 c6 50 8d 45 08 50 e8 [0-4] 8b 45 08 33 45 0c 68 b9 79 37 9e 2b f8 8d 45 fc 50 e8 [0-4] ff 4d f8 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_KY_2147838975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.KY!MTB"
        threat_id = "2147838975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 2b 4d ?? 89 4d ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CCM_2147838992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CCM!MTB"
        threat_id = "2147838992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 2b 5d ?? 89 5d ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MMZ_2147839067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MMZ!MTB"
        threat_id = "2147839067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 18 0b 53 ?? ec 04 ?? 04 ?? 30 00 00 00 75 20 00 00 eb 05 ?? ?? ?? ?? 08 74 05}  //weight: 10, accuracy: Low
        $x_10_2 = {43 16 2a c1 1c ?? 1d ?? ?? ?? ?? 55 68 ?? ?? ?? ?? 0e 3c ?? 2b 6c 9c ?? 30 3a e1 1f 00 30 17 2c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GDK_2147839106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GDK!MTB"
        threat_id = "2147839106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 31 45 ?? 2b 5d ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 89 5d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GDL_2147839183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GDL!MTB"
        threat_id = "2147839183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 89 1d ?? ?? ?? ?? 31 45 ?? 8b 45 ?? 29 45 ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c7 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? 00 31 45 ?? 2b 5d ?? 89 5d ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDC_2147839235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDC!MTB"
        threat_id = "2147839235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c6 d3 e8 03 45 cc 89 45 f8 33 45 e8 31 45 fc 2b 5d fc ff 4d dc 89 5d e0}  //weight: 2, accuracy: High
        $x_2_2 = {8a 84 30 3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? 92 02 00 00 75 08 57 57}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDD_2147839236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDD!MTB"
        threat_id = "2147839236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 84 30 3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? 7a 06 00 00 75 08 53 53}  //weight: 2, accuracy: Low
        $x_2_2 = {8b c7 d3 e8 89 45 fc 8b 45 cc 01 45 fc 8b 45 fc 33 45 e8 83 25 ?? ?? ?? ?? 00 31 45 f8 2b 5d f8 81 45 e4 ?? ?? ?? ?? ff 4d dc 89 5d e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GDM_2147839255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GDM!MTB"
        threat_id = "2147839255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {78 36 35 3d 81 6d ?? db 66 3b 70 8b 45 ?? 8b 4d ?? 31 08}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c3 c1 e0 ?? 89 5d ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 03 45 ?? 89 45 ?? ff 75 ?? 83 0d ?? ?? ?? ?? ?? 8b c3 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_WSX_2147839268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.WSX!MTB"
        threat_id = "2147839268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 89 1d ?? ?? ?? ?? 31 45 ?? 8b 45 ?? 29 45 ?? 81 45 ?? ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BX_2147839321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BX!MTB"
        threat_id = "2147839321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f8 89 45 0c 8b c7 c1 e0 04 89 7d e8 89 45 08 8b 45 e4 01 45 08 8b 45 e8 03 45 fc 89 45 f8 83 0d [0-4] ff 8b c7 c1 e8 05 03 45 e0 c7 05 [0-4] 19 36 6b ff 89 45 0c 33 45 f8 31 45 08 2b 75 08 8b 45 dc 29 45 fc ff 4d f4 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_WYV_2147839424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.WYV!MTB"
        threat_id = "2147839424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e8 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 89 1d ?? ?? ?? ?? 31 45 ?? 8b 45 ?? 29 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BY_2147839565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BY!MTB"
        threat_id = "2147839565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f8 89 45 0c 8b c7 c1 e0 04 89 7d e8 89 45 08 8b 45 e4 01 45 08 8b 45 e8 03 45 f8 89 45 fc 83 0d [0-4] ff 8b c7 c1 e8 05 03 45 e0 68 b9 79 37 9e 33 45 fc c7 05 [0-4] 19 36 6b ff 31 45 08 2b 75 08 8d 45 f8 50 e8 [0-4] ff 4d f4 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_JMT_2147839595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.JMT!MTB"
        threat_id = "2147839595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e8 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 1d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GDT_2147839632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GDT!MTB"
        threat_id = "2147839632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e0 ?? 89 7d ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 83 0d ?? ?? ?? ?? ff 81 45 ?? ?? ?? ?? ?? 8b c7 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 33 45 ?? 31 45 ?? 2b 75 ?? ff 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CW_2147839714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CW!MTB"
        threat_id = "2147839714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 45 ?? 31 45 ?? 2b 75 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CW_2147839714_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CW!MTB"
        threat_id = "2147839714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 24 01 44 24 10 8b c6 c1 e8 05 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 44 24 14 8b 44 24 28 01 44 24 14 8d 0c 33 31 4c 24 10 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 18 81 3d [0-4] 93 00 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_NEAC_2147839739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.NEAC!MTB"
        threat_id = "2147839739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 0c 33 45 08 83 25 ?? ?? ?? ?? ?? 2b d8 89 45 0c 8b c3 c1 e0 04 89 5d e8 89 45 08 8b 45 e4 01 45 08 8b 45 e8 03 45 fc 89 45 f8 ff 75 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BZ_2147839793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BZ!MTB"
        threat_id = "2147839793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e8 8b 4c 24 40 89 44 24 10 8d 44 24 10 e8 [0-4] 8b 44 24 30 31 44 24 14 8b 4c 24 10 31 4c 24 14 89 3d [0-4] 8b 44 24 1c 89 44 24 2c 8b 44 24 14 29 44 24 2c 8b 44 24 2c 89 44 24 1c 8b 44 24 44 29 44 24 18 83 eb 01 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GCW_2147839896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GCW!MTB"
        threat_id = "2147839896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e8 ?? 03 45 ?? 8d 0c 3b 33 c1 31 45 ?? 2b 75 ?? 81 c3 ?? ?? ?? ?? ff 4d ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GCX_2147839956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GCX!MTB"
        threat_id = "2147839956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e8 ?? 03 45 ?? 68 ?? ?? ?? ?? 33 c3 31 45 ?? 2b 75 ?? 8d 45 ?? 50 c7 05 ?? ?? ?? ?? 19 36 6b ff e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GEA_2147840075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GEA!MTB"
        threat_id = "2147840075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 33 c7 31 45 ?? 8b 45 ?? 29 45 ?? 68 ?? ?? ?? ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 4d ?? 8b 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GED_2147840209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GED!MTB"
        threat_id = "2147840209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 45 ?? 8d 0c 37 89 45 ?? 33 c1 31 45 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 8b 45 ?? 29 45 ?? 8b 45 ?? 81 c7 ?? ?? ?? ?? ff 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GEG_2147840387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GEG!MTB"
        threat_id = "2147840387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? ff 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_UNI_2147840473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.UNI!MTB"
        threat_id = "2147840473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GEH_2147840576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GEH!MTB"
        threat_id = "2147840576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 0c 07 c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 51 8d 45 ?? 50 c7 05 ?? ?? ?? ?? fc 03 cf ff e8 ?? ?? ?? ?? 8b 45 ?? 33 45}  //weight: 10, accuracy: Low
        $x_10_2 = {db 66 3b 70 8b 45 ?? 8b 4d ?? 31 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GEJ_2147840655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GEJ!MTB"
        threat_id = "2147840655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 0c 07 c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 51 8d 45 ?? 50 c7 05 ?? ?? ?? ?? fc 03 cf ff e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 2b f0 89 45 ?? 8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 03 fe 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GEM_2147840796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GEM!MTB"
        threat_id = "2147840796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 45 ?? 8d 0c 37 31 4d ?? 50 89 45 ?? 8d 45 ?? 50 c7 05 ?? ?? ?? ?? 19 36 6b ff e8 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 81 c7 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CA_2147840844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CA!MTB"
        threat_id = "2147840844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e8 05 03 45 e8 8d 0c 37 31 4d 08 50 89 45 0c 8d 45 08 50 c7 05 [0-4] 19 36 6b ff e8 [0-4] 8b 45 08 29 45 fc 8b 45 fc 81 c7 [0-4] ff 4d f8 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GEN_2147840870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GEN!MTB"
        threat_id = "2147840870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b f0 8b ce c1 e1 ?? 89 44 24 ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b c6 c1 e8 ?? 03 c5 50 89 44 24 ?? 8d 44 24 ?? 8d 14 37 31 54 24 ?? 50 c7 05 ?? ?? ?? ?? 19 36 6b ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_HIL_2147840905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.HIL!MTB"
        threat_id = "2147840905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 ea 03 d5 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? 50 51 8d 4c 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 81 44 24 ?? ?? ?? ?? ?? 83 ef ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GER_2147841017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GER!MTB"
        threat_id = "2147841017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 c3 50 89 45 ?? 8d 45 ?? 03 ce 31 4d ?? 50 c7 05 ?? ?? ?? ?? 19 36 6b ff e8 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 8b 45 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GES_2147841101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GES!MTB"
        threat_id = "2147841101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e8 03 c5 89 44 24 ?? 33 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 83 ef ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GEU_2147841183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GEU!MTB"
        threat_id = "2147841183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e8 03 c5 89 44 24 ?? 33 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 81 44 24 ?? 47 86 c8 61 83 ef ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GEV_2147841189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GEV!MTB"
        threat_id = "2147841189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 45 ?? 8d 0c 37 31 4d ?? 50 89 45 ?? 8d 45 ?? 50 c7 05 ?? ?? ?? ?? 19 36 6b ff e8 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GEV_2147841189_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GEV!MTB"
        threat_id = "2147841189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b7 b8 c4 23 c7 45 ?? ec 1c c1 2a c7 45 ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 46 2e d2 6c c7 45 ?? 3d e7 ce 7f c7 45 ?? 97 34 4d 72 c7 45 ?? 28 8c 70 73 c7 45 ?? a7 75 bc 74 c7 45 ?? 5e 40 4f 66 c7 85 ?? ?? ?? ?? db 81 79 6e c7 45 ?? e4 bf 0e 0d c7 85 ?? ?? ?? ?? 1b 3d 01 4c c7 85 ?? ?? ?? ?? 37 ac b2 42 c7 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CBP_2147841268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CBP!MTB"
        threat_id = "2147841268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yubuhoxofonudu" ascii //weight: 1
        $x_1_2 = "yarocaxorelabonusukevifapip" ascii //weight: 1
        $x_1_3 = "tusebuvofonakurorixe" ascii //weight: 1
        $x_1_4 = "zezafexoxijawunokofufe" ascii //weight: 1
        $x_1_5 = "rapodogaga" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MQZ_2147841295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MQZ!MTB"
        threat_id = "2147841295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 03 c5 89 44 24 ?? 33 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 ef ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GEW_2147841478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GEW!MTB"
        threat_id = "2147841478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 45 ?? 8d 0c 37 33 c8 31 4d ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 81 c7 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BMV_2147841510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BMV!MTB"
        threat_id = "2147841510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 8b 4c 24 ?? 31 4c 24 ?? 03 c3 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75 ?? 55 55 55 55 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 81 44 24 ?? ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RMV_2147841568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RMV!MTB"
        threat_id = "2147841568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4c 24 ?? 31 4c 24 ?? 03 c3 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75 ?? 55 55 55 55 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_XII_2147841908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.XII!MTB"
        threat_id = "2147841908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 03 c5 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75 ?? 57 57 57 57 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_XIM_2147842037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.XIM!MTB"
        threat_id = "2147842037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 ?? 03 45 ?? 03 de 33 d8 31 5d ?? 2b 7d ?? 68 ?? ?? ?? ?? 8d 45 ?? 50 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CC_2147842106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CC!MTB"
        threat_id = "2147842106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 10 33 44 24 2c c7 05 [0-4] 00 00 00 00 2b d0 8b ca c1 e1 04 89 44 24 10 89 4c 24 2c 8b 44 24 20 01 44 24 2c 8b c2 c1 e8 05 03 c5 03 fa 33 f8 8b 44 24 2c 33 c7 2b f0 68 b9 79 37 9e 8d 44 24 18 50 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff e8 [0-4] 4b 0f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CD_2147842112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CD!MTB"
        threat_id = "2147842112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 10 33 44 24 30 c7 05 [0-4] 00 00 00 00 2b f0 8b ce c1 e1 04 89 44 24 10 89 4c 24 30 8b 44 24 20 01 44 24 30 8b c6 c1 e8 05 03 44 24 24 03 de 33 d8 8b 44 24 30 68 b9 79 37 9e 33 c3 8d 54 24 18 52 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 2b f8 e8 [0-4] 4d 0f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_XAA_2147842117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.XAA!MTB"
        threat_id = "2147842117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 44 24 ?? 03 de 33 d8 8b 44 24 ?? 68 ?? ?? ?? ?? 33 c3 8d 54 24 ?? 52 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f8 e8 ?? ?? ?? ?? 4d 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CE_2147842259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CE!MTB"
        threat_id = "2147842259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 2c 89 44 24 20 8b 44 24 28 01 44 24 20 8b 44 24 2c c1 e8 05 89 44 24 14 8b 4c 24 38 8d 44 24 14 c7 05 [0-4] ee 3d ea f4 e8 [0-4] 8b 44 24 20 31 44 24 10 8b 44 24 10 31 44 24 14 81 3d [0-4] 13 02 00 00 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CF_2147842319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CF!MTB"
        threat_id = "2147842319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 28 89 44 24 20 8b 44 24 24 01 44 24 20 8b 44 24 28 c1 e8 05 89 44 24 14 8b 4c 24 34 8d 44 24 14 c7 05 [0-4] ee 3d ea f4 e8 [0-4] 8b 44 24 20 31 44 24 10 8b 44 24 10 31 44 24 14 81 3d [0-4] 13 02 00 00 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CG_2147842387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CG!MTB"
        threat_id = "2147842387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 10 33 44 24 28 c7 05 [0-4] 00 00 00 00 2b d0 8b ca c1 e1 04 89 44 24 10 89 4c 24 28 8b 44 24 1c 01 44 24 28 8b c2 c1 e8 05 03 c5 8d 0c 17 33 c8 8b 44 24 28 33 c1 2b f0 81 c7 [0-4] 4b c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 0f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GFM_2147842414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GFM!MTB"
        threat_id = "2147842414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 89 7d ?? e8 ?? ?? ?? ?? 8b 45 ?? 01 45 ?? 33 d2 89 55 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? ?? 01 45 ?? 8b 45 ?? 89 45 ?? 8b 4d ?? 8b c7 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPX_2147842505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPX!MTB"
        threat_id = "2147842505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 33 c6 89 45 fc 2b f8 8b 45 cc 29 45 f8 83 6d e0 01 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPX_2147842505_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPX!MTB"
        threat_id = "2147842505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 14 33 83 ff 0f 75 4d 6a 00 6a 00 6a 00 ff d5 6a 2e 8d 44 24 10 6a 00 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPX_2147842505_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPX!MTB"
        threat_id = "2147842505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 8d f8 fb ff ff 30 04 39 83 fb 0f 75 1f 56 8d 85 fc fb ff ff 50 56 56 56 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPX_2147842505_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPX!MTB"
        threat_id = "2147842505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 75 05 74 03 e3 1c 2c 8b 1c 24 83 c4 04 eb 0a 08 81 eb dc 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPX_2147842505_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPX!MTB"
        threat_id = "2147842505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 04 8d 8d 78 ff ff ff 51 8b 8f a4 00 00 00 83 c1 08 51 ff 75 90 ff d0 8b 45 ac 6a 40 68 00 30 00 00 8d 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPX_2147842505_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPX!MTB"
        threat_id = "2147842505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 ff d6 ff d7 4b 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = {56 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d3 6a 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPX_2147842505_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPX!MTB"
        threat_id = "2147842505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 45 f0 8b 45 f8 33 45 f0 2b f0 89 45 f8 8b c6 c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 4d f4 8d 04 33 89 45 e8 8b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPX_2147842505_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPX!MTB"
        threat_id = "2147842505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f0 83 45 f8 64 29 45 f8 83 6d f8 64 8b 55 f8 c1 e2 04 89 55 fc 8b 45 e4 01 45 fc 8b 4d f8 8b f1 c1 ee 05 03 75 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPX_2147842505_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPX!MTB"
        threat_id = "2147842505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 44 24 20 8b 44 24 20 89 44 24 18 8b 4c 24 28 8b c7 d3 e8 89 44 24 14 8b 44 24 ?? 01 44 24 14 8b 44 24 14 33 44 24 18 31 44 24 10 8b 44 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPX_2147842505_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPX!MTB"
        threat_id = "2147842505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d4 01 45 fc 83 65 f0 00 8b 45 e8 01 45 f0 8b 45 e4 90 01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b c7 d3 e8 03 45 d0 89 45 f8 8b 45 ec 31 45 fc 8b 45 fc 33 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPY_2147842506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPY!MTB"
        threat_id = "2147842506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 40 04 ff 70 09 6a 00 8b 45 08 ff 50 24 89 45 f8 83 65 f4 00 6a 00 8d 45 f4 50 ff 75 f8 8b 45 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPY_2147842506_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPY!MTB"
        threat_id = "2147842506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b c6 d3 e8 8b 4c 24 10 03 c5 89 44 24 14 33 44 24 20 33 c8 8d 44 24 28 89 4c 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPY_2147842506_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPY!MTB"
        threat_id = "2147842506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d4 01 45 fc 89 5d f4 8b 45 e8 01 45 f4 8b 45 d0 90 01 45 f4 8b 45 f4 89 45 ec 8b 4d f0 8b c6 d3 e8 8b 4d ec 31 4d fc 03 45 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPY_2147842506_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPY!MTB"
        threat_id = "2147842506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 84 24 60 02 00 00 ea 13 30 0a c7 84 24 74 02 00 00 0a 4b 19 39 c7 84 24 04 03 00 00 3e 5c d5 18 c7 84 24 c8 01 00 00 e9 d6 86 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPY_2147842506_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPY!MTB"
        threat_id = "2147842506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 6a 40 8b 85 58 ff ff ff ff 70 0a ff b5 50 ff ff ff ff 55 d8 89 45 f4 8b 85 50 ff ff ff 89 85 68 ff ff ff 8b 85 58 ff ff ff ff 70 0a 6a 00 ff b5 50 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RPY_2147842506_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RPY!MTB"
        threat_id = "2147842506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 0e fc ff ff 33 c6 85 11 fc ff ff 6e c6 85 06 fc ff ff 54 c6 85 13 fc ff ff 70 c6 85 0f fc ff ff 32 c6 85 01 fc ff ff 72 c6 85 09 fc ff ff 6c c6 85 15 fc ff ff 68 c6 85 14 fc ff ff 73 c6 85 04 fc ff ff 74 c6 85 12 fc ff ff 61 c6 85 10 fc ff ff 53 c6 85 03 fc ff ff 61 c6 85 18 fc ff ff 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CH_2147842508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CH!MTB"
        threat_id = "2147842508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b c3 d3 e8 03 45 d0 89 45 f8 8b 45 ec 31 45 fc 8b 45 fc 33 45 f8 29 45 e4 89 45 fc 8d 45 e8 e8 [0-4] ff 4d e0 0f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CI_2147842723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CI!MTB"
        threat_id = "2147842723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b c6 d3 e8 8b 4c 24 10 03 44 24 34 89 44 24 14 33 44 24 20 33 c8 2b f9 8d 44 24 24 89 4c 24 10 89 7c 24 28 e8 [0-4] 83 eb 01 0f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CJ_2147842724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CJ!MTB"
        threat_id = "2147842724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 28 89 44 24 20 8b 44 24 24 01 44 24 20 8b 44 24 28 c1 e8 05 89 44 24 14 8b 4c 24 30 8d 44 24 14 c7 05 [0-4] ee 3d ea f4 e8 [0-4] 8b 44 24 20 31 44 24 10 8b 4c 24 10 31 4c 24 14 81 3d [0-4] 13 02 00 00 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CK_2147842798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CK!MTB"
        threat_id = "2147842798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 14 33 44 24 10 c7 05 [0-4] 00 00 00 00 2b d0 89 44 24 14 8b c2 c1 e0 04 89 44 24 10 8b 44 24 20 01 44 24 10 8b c2 c1 e8 05 03 c5 8d 0c 17 33 c8 8b 44 24 10 33 c1 2b f0 81 c7 47 86 c8 61 4b c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 0f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CL_2147842810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CL!MTB"
        threat_id = "2147842810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 14 33 44 24 10 c7 05 [0-4] 00 00 00 00 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 24 01 44 24 10 8b c6 c1 e8 05 03 44 24 28 8d 0c 37 33 c8 8b 44 24 10 33 c1 2b d8 81 c7 47 86 c8 61 ff 4c 24 18 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 0f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_OVM_2147842880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.OVM!MTB"
        threat_id = "2147842880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 c5 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 81 44 24 ?? ?? ?? ?? ?? 83 ef ?? 8b 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_HKK_2147842996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.HKK!MTB"
        threat_id = "2147842996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 c5 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 83 ef ?? 8b 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CM_2147843036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CM!MTB"
        threat_id = "2147843036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 28 89 44 24 24 8b 44 24 10 01 44 24 24 8b 44 24 28 c1 e8 05 89 44 24 18 8b 4c 24 44 8d 44 24 18 c7 05 [0-4] ee 3d ea f4 e8 [0-4] 8b 44 24 24 31 44 24 14 8b 44 24 14 31 44 24 18 81 3d [0-4] 13 02 00 00 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CN_2147843039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CN!MTB"
        threat_id = "2147843039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 28 89 44 24 20 8b 44 24 14 01 44 24 20 8b 44 24 28 c1 e8 05 89 44 24 18 8b 4c 24 30 8d 44 24 18 c7 05 [0-4] ee 3d ea f4 e8 [0-4] 8b 44 24 20 31 44 24 10 8b 44 24 10 31 44 24 18 81 3d [0-4] 13 02 00 00 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_KIN_2147843240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.KIN!MTB"
        threat_id = "2147843240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 c1 ee ?? 03 74 24 ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 53 53 8d 4c 24 ?? 51 ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 33 ce 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 83 6c 24 ?? ?? 8b 54 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CO_2147843282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CO!MTB"
        threat_id = "2147843282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 28 89 44 24 20 8b 44 24 14 01 44 24 20 8b 4c 24 1c d3 ea 8b 4c 24 38 8d 44 24 24 c7 05 [0-4] ee 3d ea f4 89 54 24 24 e8 [0-4] 8b 44 24 20 31 44 24 10 8b 74 24 24 33 74 24 10 81 3d [0-4] 13 02 00 00 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CPY_2147843333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CPY!MTB"
        threat_id = "2147843333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ce c1 e9 ?? 03 4c 24 28 8d 04 33 31 44 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 14 8b 44 24 14 31 44 24 10 2b 7c 24 10 81 c3 ?? ?? ?? ?? ff 4c 24 18 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CPZ_2147843334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CPZ!MTB"
        threat_id = "2147843334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c6 c1 e8 ?? 03 c5 89 44 24 14 8b 44 24 1c 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 28 89 4c 24 10 e8 7d fe ff ff 81 44 ?? ?? ?? ?? ?? ?? 83 ef 01 8b 4c 24 28 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GFX_2147843373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GFX!MTB"
        threat_id = "2147843373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f7 c1 ee ?? 03 74 24 ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 33 ce 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 81 44 24 ?? 47 86 c8 61 83 6c 24 ?? ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CP_2147843415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CP!MTB"
        threat_id = "2147843415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 24 89 44 24 1c 8b 44 24 20 01 44 24 1c 8b 4c 24 10 d3 ee 8b 4c 24 34 8d 44 24 28 c7 05 [0-4] ee 3d ea f4 89 74 24 28 e8 [0-4] 8b 44 24 1c 31 44 24 14 8b 74 24 28 33 74 24 14 81 3d [0-4] 13 02 00 00 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CQ_2147843416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CQ!MTB"
        threat_id = "2147843416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 44 24 18 8b 44 24 18 89 44 24 1c 8b f7 c1 ee 05 03 f5 8b 44 24 1c 31 44 24 10 81 3d [0-4] 21 01 00 00 75}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 4c 24 10 33 ce 8d 44 24 24 89 4c 24 10 e8 [0-4] 81 44 24 20 47 86 c8 61 83 6c 24 2c 01 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_NEAD_2147843457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.NEAD!MTB"
        threat_id = "2147843457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b f0 89 44 24 ?? 8b c6 c1 e0 ?? 89 44 24 10 8b 44 24 28 01 44 24 10 8b 44 24 18 8b d6 c1 ea ?? 03 d5 03 c6 31 44 24}  //weight: 10, accuracy: Low
        $x_5_2 = {b5 02 8a 94 31 d6 38 00 00 88 14 30 81 c4 18 0c 00 00 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CPVV_2147843500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CPVV!MTB"
        threat_id = "2147843500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 44 24 14 8b c6 c1 e0 ?? 89 44 24 10 8b 44 24 28 01 44 24 10 8b 44 24 18 8b d6 c1 ea ?? 03 d5 03 c6 31 44 24 10 c7 05 [0-10] c7 05 [0-10] 89 54 24 14 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 2c 29 44 24 18 4b 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CST_2147843532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CST!MTB"
        threat_id = "2147843532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 c1 ea ?? 03 d5 8d 04 37 31 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 0d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 74 ?? 81 c7 ?? ?? ?? ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CR_2147843537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CR!MTB"
        threat_id = "2147843537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 24 01 44 24 14 8b 44 24 14 33 c3 33 44 24 10 c7 05 [0-4] 00 00 00 00 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 28 01 44 24 10 8b ce c1 e9 05 03 cd 8d 14 37 31 54 24 10 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 4c 24 14 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 18}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AXX_2147843677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AXX!MTB"
        threat_id = "2147843677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 ?? 03 44 24 ?? 33 44 24 ?? 33 c8 51 8b c6 89 4c 24 ?? e8 ?? ?? ?? ?? 8b f0 8d 44 24 ?? 89 74 ?? 24 e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CS_2147843745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CS!MTB"
        threat_id = "2147843745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 24 89 44 24 1c 8b 44 24 20 01 44 24 1c 8b 4c 24 10 8b c3 d3 e8 8b 4c 24 30 c7 05 [0-4] ee 3d ea f4 89 44 24 24 8d 44 24 24 e8 [0-4] 8b 44 24 1c 31 44 24 14 8b 74 24 24 33 74 24 14 81 3d [0-4] 13 02 00 00 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AXB_2147843768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AXB!MTB"
        threat_id = "2147843768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 c1 ee ?? 03 74 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? ff 15 ?? ?? ?? ?? 8b 44 24 ?? 33 c6 89 44 24 ?? 50 8b c3 e8 ?? ?? ?? ?? 8b d8 8d 44 24 ?? 89 5c 24 ?? e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_HGL_2147843922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.HGL!MTB"
        threat_id = "2147843922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f3 c1 ee ?? 03 74 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 6a ?? ff 15 ?? ?? ?? ?? 8b 44 24 ?? 33 c6 89 44 24 ?? 50 8b c7 e8 ?? ?? ?? ?? 81 44 24 ?? ?? ?? ?? ?? 83 6c 24 ?? ?? 8b f8 89 7c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_C_2147844290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.C!MTB"
        threat_id = "2147844290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 ea 03 c7 03 55 d8 33 d0 31 55 f8 8b 45 f8 29 45 ec 8b 45 e0 29 45 f4 ff 4d e4 0f 85 f2 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_C_2147844290_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.C!MTB"
        threat_id = "2147844290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 ff 8b 45 08 0f be 04 10 69 c0}  //weight: 2, accuracy: High
        $x_2_2 = {03 ce 8b 55 0c 03 55 ?? 88 0a 0f be 45 ?? 8b 4d 0c 03 4d ?? 0f b6 11 2b d0 8b 45 0c 03 45 ?? 88 10 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_XIG_2147844981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.XIG!MTB"
        threat_id = "2147844981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? 31 7c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 29 44 24 ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PAZ_2147845369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PAZ!MTB"
        threat_id = "2147845369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e0 04 89 45 08 8b 45 e8 01 45 08 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 05 03 45 e4 03 fe 31 7d 08 50 89 45 0c 8d 45 08 50 c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BKK_2147845469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BKK!MTB"
        threat_id = "2147845469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 eb 03 8d 49 00 8d b5 ?? ?? ff ff c7 85 ?? ?? ff ff 00 00 00 00 e8 ?? ?? ff ff 8a 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 30 14 38 83 fb 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BKK_2147845469_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BKK!MTB"
        threat_id = "2147845469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 ea 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {01 44 24 1c 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b c7 c1 e8 ?? 51 03 c5 50 8d 54 24 ?? 52 89 4c 24 ?? e8 ?? ?? ?? ?? 2b 74 24 ?? 89 74 24 ?? 8b 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CT_2147845689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CT!MTB"
        threat_id = "2147845689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 44 24 20 8b 44 24 20 89 44 24 18 8b 4c 24 10 33 4c 24 18 8b c6 c1 e8 05 51 03 c3 50 8d 54 24 18 52 89 4c 24 1c e8 [0-4] 8b 44 24 10 29 44 24 14 81 44 24 24 47 86 c8 61 83 ed 01 0f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CU_2147845927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CU!MTB"
        threat_id = "2147845927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e0 04 89 44 24 10 8b 44 24 28 01 44 24 10 8b ce c1 e9 05 03 cb 8d 14 37 31 54 24 10 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 4c 24 14 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 18 81 3d [0-4] 93 00 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CV_2147846214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CV!MTB"
        threat_id = "2147846214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 2c 01 44 24 0c 8b d7 c1 ea 05 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 54 24 10 8b 44 24 24 01 44 24 10 8d 04 3b 31 44 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 81 3d [0-4] 93 00 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CX_2147846369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CX!MTB"
        threat_id = "2147846369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d6 c1 ea 05 03 ce c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 54 24 14 8b 44 24 2c 01 44 24 14 31 4c 24 0c 8b 44 24 14 31 44 24 0c 8b 44 24 0c 29 44 24 10 81 3d [0-4] 93 00 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CY_2147846371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CY!MTB"
        threat_id = "2147846371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 24 89 44 24 20 8b 44 24 28 01 44 24 20 8b 4c 24 18 8b c6 d3 e8 8b 4c 24 30 c7 05 [0-4] ee 3d ea f4 89 44 24 24 8d 44 24 24 e8 [0-4] 8b 44 24 20 31 44 24 10 81 3d [0-4] e6 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CATZ_2147846463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CATZ!MTB"
        threat_id = "2147846463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 88 10 40 00 6a 00 ff ?? ?? ?? ?? ?? 6a 00 6a 00 8d 44 24 48 50 ff ?? ?? ?? ?? ?? 6a 00 8d 8c 24 44 08 00 00 51 ff 15 24 10 40 00 6a 00 ff 15 e4 10 40 00 6a 00 8d 94 24 44 18 00 00 52 68 a0 4b 40 00 ff 15 28 10 40 00 8d 84 24 40 10 00 00 50 6a 00 68 b8 4b 40 00 68 00 4c 40 00 ff 15 14 11 40 00 6a 00 ff 15 c8 10 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDE_2147846605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDE!MTB"
        threat_id = "2147846605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 44 24 1c 8b 44 24 1c 89 44 24 20 8b 4c 24 18 8b 54 24 14 d3 ea 8b cb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RLL_2147846726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RLL!MTB"
        threat_id = "2147846726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b cb 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 51 52 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 ed ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDF_2147846730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDF!MTB"
        threat_id = "2147846730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 44 24 24 8b 44 24 24 89 44 24 20 8b 4c 24 1c 8b 54 24 18 d3 ea 8b cb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CREX_2147846741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CREX!MTB"
        threat_id = "2147846741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 31 44 24 10 8b 4c 24 10 8b 54 24 28 51 52 8d 44 24 18 50 e8 ?? ?? ?? ?? 8b 44 24 10 29 44 24 14 8d 44 24 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 04 24 00 00 00 00 8b 44 24 48 89 04 24 8b 44 24 44 31 04 24 8b 04 24 8b 4c 24 40 89 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_EM_2147847200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.EM!MTB"
        threat_id = "2147847200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {99 b9 12 00 00 00 f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_YX_2147847456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.YX!MTB"
        threat_id = "2147847456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 b1 4a 94 a1 ?? ?? ?? ?? 32 0c 46 5a 5a 02 b1 ?? ?? ?? ?? ae b5 ?? 56 05 ?? ?? ?? ?? 30 14 03 b1 5f 28 b4 b1 ?? ?? ?? ?? ac a5 a5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PHR_2147847910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PHR!MTB"
        threat_id = "2147847910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 8b 4c 24 ?? 03 c7 89 44 24 ?? 8d 44 24 2c 89 54 24 2c c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 24 31 44 24 14 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ee 03 74 24 ?? 8b 44 24 ?? 31 44 24 14 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 53 53 53 ff 15 ?? ?? ?? ?? 8b 44 24 14 33 c6 89 44 24 14 2b f8 8d 44 24 ?? e8 ?? ?? ?? ?? 83 6c 24 34 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASE_2147848011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASE!MTB"
        threat_id = "2147848011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 8b 4c 24 ?? 03 c7 89 44 24 ?? 8d 44 24 28 89 54 24 28 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 24 31 44 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ?? 53 53 ff 15 ?? ?? ?? ?? 8b 44 24 10 31 44 24 28 8b 44 24 28 83 44 24 18 ?? 29 44 24 18 83 6c 24 18 ?? 8b 44 24 18 8d 4c 24 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PBA_2147848019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PBA!MTB"
        threat_id = "2147848019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 33 44 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f0 8b ce c1 e1 04 89 44 24 14 89 4c 24 10 8b 44 24 2c 01 44 24 10 8b d6 c1 ea 05}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 c4 3f 40 00 ff 15 ?? ?? ?? ?? 8b 4c 24 14 8b 44 24 10 33 cf 33 c1 2b e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PBB_2147848038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PBB!MTB"
        threat_id = "2147848038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 c7 04 24 ?? ?? ?? ?? 8b 44 24 08 83 2c 24 04 01 04 24 8b 04 24 31 01 59}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 18 33 44 24 14 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f8 8b cf c1 e1 04}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 18 8b 44 24 14 33 d6 33 c2 2b d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_VKL_2147848897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.VKL!MTB"
        threat_id = "2147848897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 ?? 8d 34 2f c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10 8b 44 24 ?? 01 44 24 10 8b 0d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75 ?? 8d 4c 24 30 51 6a 00 ff 15 ?? ?? ?? ?? 8b 0d cc b7 49 00 8b 54 24 10 8b 44 24 ?? 33 d6 33 c2 2b d8 81 f9 ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DH_2147848949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DH!MTB"
        threat_id = "2147848949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e2 04 89 54 24 14 8b 44 24 24 01 44 24 14 8b c7 c1 e8 05 8d 34 2f c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 44 24 10 8b 44 24 20 01 44 24 10 8b 0d [0-4] 81 f9 79 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CRIZ_2147849034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CRIZ!MTB"
        threat_id = "2147849034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 04 24 8b 04 24 31 01}  //weight: 1, accuracy: High
        $x_1_2 = {33 c7 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_SE_2147849048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.SE!MTB"
        threat_id = "2147849048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 04 24 04 00 00 00 8b 44 24 08 83 2c 24 04 01 04 24 8b 04 24 31 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_H_2147849245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.H!MTB"
        threat_id = "2147849245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 cf 31 4c 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 15 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 74 ?? 8d 44 24}  //weight: 2, accuracy: Low
        $x_2_2 = {33 c7 33 c1 2b f0 8b ce c1 e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_H_2147849245_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.H!MTB"
        threat_id = "2147849245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 c1 ea 05 03 54 24 24 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 d7 31 54 24 14 c7 05 ?? ?? ?? ?? ff ff ff ff 8b 44 24 14 29 44 24 18 8b 44 24 28 29 44 24 10 ff 4c 24 1c 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DJ_2147849532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DJ!MTB"
        threat_id = "2147849532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4c 24 1c 8b 44 24 28 8b d7 d3 ea 8b 4c 24 40 03 c7 89 44 24 24 8d 44 24 2c 89 54 24 2c c7 05 [0-4] ee 3d ea f4 e8 [0-4] 8b 44 24 24 31 44 24 14 81 3d [0-4] e6 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AYT_2147849566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AYT!MTB"
        threat_id = "2147849566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce c1 e9 ?? 8d 3c 33 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 18 8b 44 24 28 01 44 24 18 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 54 24 38 52 6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 18 8b 44 24 14 33 cf 33 c1 2b e8 8d 44 24 ?? e8 73 ?? ?? ?? ?? 4c 24 20 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_REE_2147849672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.REE!MTB"
        threat_id = "2147849672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 44 24 14 8b 44 24 30 01 44 24 14 8b 44 24 24 31 44 24 ?? 8b 4c 24 10 8b 54 24 ?? 51 52 8d 44 24 18 50 e8 ?? ?? ?? ?? 8b 4c 24 10 8d 44 24 2c e8 ?? ?? ?? ?? 81 c7 47 86 c8 61 83 ed 01 89 7c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DK_2147849733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DK!MTB"
        threat_id = "2147849733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c7 33 c1 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 2c 01 44 24 10 81 3d [0-4] be 01 00 00 8d 3c 2e 75}  //weight: 2, accuracy: Low
        $x_2_2 = {8b ce c1 e9 05 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 4c 24 14 8b 44 24 24 01 44 24 14 81 3d [0-4] 79 09 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DL_2147849766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DL!MTB"
        threat_id = "2147849766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 0c 37 89 4c 24 24 8b 4c 24 1c d3 ee 8b 4c 24 38 8d 44 24 14 c7 05 [0-4] ee 3d ea f4 89 74 24 14 e8 [0-4] 8b 44 24 24 31 44 24 10 81 3d [0-4] e6 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DM_2147850082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DM!MTB"
        threat_id = "2147850082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 0c 37 89 4c 24 20 8b 4c 24 1c d3 ee 8b 4c 24 3c 8d 44 24 14 c7 05 [0-4] ee 3d ea f4 89 74 24 14 e8 [0-4] 8b 44 24 20 31 44 24 10 81 3d [0-4] e6 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DN_2147850110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DN!MTB"
        threat_id = "2147850110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 ce 89 4c 24 20 8b 4c 24 1c d3 ee 8b 4c 24 3c 8d 44 24 14 c7 05 [0-4] ee 3d ea f4 89 74 24 14 e8 [0-4] 8b 44 24 20 31 44 24 10 81 3d [0-4] e6 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DO_2147850176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DO!MTB"
        threat_id = "2147850176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c1 8d 0c 3b 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 14 89 54 24 10 8b 44 24 24 01 44 24 10 81 3d [0-4] be 01 00 00 8d 2c 33 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DP_2147850611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DP!MTB"
        threat_id = "2147850611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c6 c1 e8 05 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 44 24 14 8b 44 24 24 01 44 24 14 8b 4c 24 14 8b 44 24 10 33 cb 33 c1 2b f8 8d 44 24 1c e8 [0-4] ff 4c 24 18 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DQ_2147850615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DQ!MTB"
        threat_id = "2147850615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c6 c1 e8 05 c7 05 [0-4] 19 36 6b ff c7 05 [0-4] ff ff ff ff 89 44 24 14 8b 44 24 24 01 44 24 14 8b 4c 24 14 8b 44 24 10 33 cd 33 c1 89 44 24 10 2b d8 c7 44 24 18 00 00 00 00 8b 44 24 2c 01 44 24 18 2b 7c 24 18 ff 4c 24 1c 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DR_2147850631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DR!MTB"
        threat_id = "2147850631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4c 24 18 8d 04 37 d3 ee 8b 4c 24 30 89 44 24 2c 8d 44 24 14 89 74 24 14 c7 05 [0-4] ee 3d ea f4 e8 [0-4] 8b 44 24 2c 31 44 24 10 81 3d [0-4] e6 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DS_2147850633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DS!MTB"
        threat_id = "2147850633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4c 24 18 8d 14 37 d3 ee 8b 4c 24 2c 8d 44 24 1c 89 54 24 28 89 74 24 1c c7 05 [0-4] ee 3d ea f4 e8 [0-4] 8b 44 24 28 31 44 24 10 81 3d [0-4] e6 09 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PMV_2147850778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PMV!MTB"
        threat_id = "2147850778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 00 36 4a 70 ?? c7 86 01 ff 82 03 7d db 4b 63 88 27 bb 5a 21 68 70 d3 09 6b 89 fe 8c 26 ba 5a 20 68 70 61 9e 2d f7 ea e5 48 e2 ?? 98 8a 8a 01 8e ae 09 4e 8e 61 8f 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CBI_2147851247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CBI!MTB"
        threat_id = "2147851247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 ?? 03 44 24 ?? 03 cb 33 c2 33 c1 2b f0 8b d6 c1 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 14 33 d7 31 54 24 0c 8b 44 24 0c 29 44 24 10 8b 3d ?? ?? ?? ?? 81 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ZIT_2147851286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ZIT!MTB"
        threat_id = "2147851286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ff ff ff ff 89 44 24 18 8b 44 24 2c 01 44 24 18 81 3d ?? ?? ?? ?? 79 09 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 4c 24 18 33 cf 31 4c 24 10 8b 44 24 10 29 44 24 14 8b 3d ?? ?? ?? ?? 81 ff 93 00 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_YBB_2147852421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.YBB!MTB"
        threat_id = "2147852421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 65 fc 00 8b 45 10 89 45 fc 8b 45 0c 31 45 fc 8b 45 fc 8b 4d 08 89 01 c9 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_YBC_2147852442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.YBC!MTB"
        threat_id = "2147852442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 44 24 20 03 cd 33 c1 8d 0c 33 33 c1 2b f8 8b d7 c1 e2 04 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d3 33 c2 89 44 24 10 2b f0 8d 44 24 18 e8 ?? ?? ?? ?? ff 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RB_2147852571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RB!MTB"
        threat_id = "2147852571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 a9 2a 6f db ad 44 ad 44 a8 68 ea 53 af af af af 44 a2 9c 90 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RB_2147852571_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RB!MTB"
        threat_id = "2147852571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 67 88 2a c7 84 24 ?? ?? ?? ?? 60 c3 73 76 c7 84 24 ?? ?? ?? ?? 41 59 8d 4d c7 84 24 ?? ?? ?? ?? 9f f8 ff 08 c7 84 24 ?? ?? ?? ?? 5f 05 09 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AJ_2147852636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AJ!MTB"
        threat_id = "2147852636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ac a8 ac ac 49 f5 ab ee 34 48 fd 00 47 47 47 ac 42 e4 5d ac b2 88 af}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_LKAE_2147852870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.LKAE!MTB"
        threat_id = "2147852870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3d 54 40 8f 01 ?? ?? 00 00 a1 b8 4a 8f 01 8a 84 18 4b 13 01 00 8b 0d 74 5d 8d 01 88 04 19 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 ff 35 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RD_2147853114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RD!MTB"
        threat_id = "2147853114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 54 24 24 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDH_2147853228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDH!MTB"
        threat_id = "2147853228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d0 c1 ea 05 03 54 24 24 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_NIV_2147888107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.NIV!MTB"
        threat_id = "2147888107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 8d 4d f8 e8 ?? ?? ?? ?? 8b 45 ?? 01 45 f8 8b 4d f0 8b 45 f4 8b d3 d3 ea 03 c3 03 55 ?? 33 d0 31 55 f8 2b 7d f8 89 7d e8 8b 45 e4 29 45 f4 ff 4d ec 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AEH_2147888119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AEH!MTB"
        threat_id = "2147888119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 6c 58 6a 6d 66 a3 ?? ?? ?? ?? 58 6a 69 66 a3 ?? ?? ?? ?? 58 6a 67 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 33 66 a3 ?? ?? ?? ?? 33 c0 66 a3 ?? ?? ?? ?? 58 6a 73 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDI_2147888238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDI!MTB"
        threat_id = "2147888238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d f0 8b 45 f4 8b f3 d3 ee 03 c3 89 45 ec}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AMAB_2147888269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AMAB!MTB"
        threat_id = "2147888269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1b 27 f9 45 37 3b 3e 00 b7 76 59 9c 78 9c ec 99 0c 83 0c 76 b7 44 e4 34 4f 30 0c 8b b1 85 0d 0d a7 c9 cb d0 f3 5d a5 39 4b 32}  //weight: 1, accuracy: High
        $x_1_2 = {6b b5 e0 8b 1c 24 83 c4 04 eb 0a 4c 81 eb 06 32 00 00 eb 05 28 eb f5 4c 28 74 08 75 06 c9 9f 88 54 50 84 83 ec 04 c7 04 24 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "KB_/YB]NXK/YBBJBL/YM@WHZ/YM@W\\I/YM@WB@/YM@WYF/YM@WKF/YF@\\J]//qp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDJ_2147888675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDJ!MTB"
        threat_id = "2147888675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 75 e4 8b 45 d4 31 45 f8 33 75 f8 81 3d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RG_2147888868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RG!MTB"
        threat_id = "2147888868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {12 a9 31 bb be be 19 16 c8 86 c1 7e 41 35 5f 16 17 be d2 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RG_2147888868_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RG!MTB"
        threat_id = "2147888868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 dc 01 45 fc 8b 4d f8 8b 45 f4 8b fb d3 ef 03 c3 31 45 fc 03 7d d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RG_2147888868_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RG!MTB"
        threat_id = "2147888868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 d3 ee 8d 04 3b 89 45 e0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 e4 8b 45 e0 31 45 fc 33 75 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RG_2147888868_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RG!MTB"
        threat_id = "2147888868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf c1 e9 05 03 4c 24 ?? 8b d7 c1 e2 04 03 54 24 ?? 8d 04 2f 33 ca 33 c8 2b d9 8b cb c1 e1 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RG_2147888868_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RG!MTB"
        threat_id = "2147888868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 4d ?? 8d 14 03 d3 e8 03 45 ?? 33 c2 31 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RG_2147888868_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RG!MTB"
        threat_id = "2147888868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 85 54 fe ff ff dd 8a 30 3f c7 85 5c fe ff ff 1a a0 a6 15 c7 85 8c fe ff ff cb 2e 4a 32 c7 85 cc fd ff ff 37 5f 18 1f c7 85 d4 fd ff ff 3f 18 79 15 c7 85 14 fe ff ff 42 ac ee 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_WEE_2147889288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.WEE!MTB"
        threat_id = "2147889288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c7 d3 ef 89 45 e4 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d d8 8b 45 e4 31 45 fc 33 7d fc 81 3d ?? ?? ?? ?? 13 02 00 00 75 0b 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 2b df 83 3d ?? ?? ?? ?? 0c 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 dc 01 45 fc 8b 4d f8 8b 45 f4 8b fb d3 ef 03 c3 31 45 fc 03 7d d4 81 3d ?? ?? ?? ?? 21 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDL_2147889319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDL!MTB"
        threat_id = "2147889319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 7d d8 8b 45 e4 31 45 fc 33 7d fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_WEF_2147889383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.WEF!MTB"
        threat_id = "2147889383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 54 24 24 8b f0 c1 e6 04 03 f5 33 d6 03 c1 33 d0 2b fa 8b d7 c1 e2 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 14 8b 44 24 28 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8d 1c 39 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? 8d 4c 24 78 51 6a 00 ff 15 ?? ?? ?? ?? 33 f3 31 74 24 14 8b 44 24 14 29 44 24 18 8d 44 24 1c e8 ?? ?? ?? ?? ff 4c 24 20 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_I_2147890060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.I!MTB"
        threat_id = "2147890060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 44 24 24 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 c3 31 44 24 10 c7 05 ?? ?? ?? ?? ff ff ff ff 8b 44 24 10 29 44 24 14 81 c7 47 86 c8 61 4d 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_I_2147890060_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.I!MTB"
        threat_id = "2147890060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 45 fc d3 ef 03 7d d4 81 3d f4 ec 41 02}  //weight: 2, accuracy: High
        $x_2_2 = {31 7d fc 8b 45 fc 29 45 f4 81 c3 ?? ?? ?? ?? ff 4d e8 0f}  //weight: 2, accuracy: Low
        $x_2_3 = {03 7d e4 8b 45 e0 31 45 fc 33 7d fc 81 3d f4 ec 41 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_QAC_2147890105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.QAC!MTB"
        threat_id = "2147890105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 1c 0e c1 e9 05 83 3d 24 9f 2d 02 1b 89 44 24 10 8b e9 75 0a ff 15 44 10 40 00 8b 44 24 10 03 6c 24 20 c7 05 ?? ?? ?? ?? 00 00 00 00 33 eb 33 e8 2b fd 8b d7 c1 e2 04 89 54 24 10 8b 44 24 28 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d 1c 3e 75}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 ff 15 ?? ?? ?? ?? 8d 4c 24 78 51 6a 00 ff 15 ?? ?? ?? ?? 33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 8d 44 24 18 e8 ?? ?? ?? ?? ff 4c 24 1c 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CRI_2147890111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CRI!MTB"
        threat_id = "2147890111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 ea 03 c6 89 45 e8 03 55 d4 8b 45 e8 31 45 fc 31 55 fc 2b 7d fc 8b 45 ?? 29 45 f8 ff 4d e4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CRI_2147890111_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CRI!MTB"
        threat_id = "2147890111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ee 8b 4d d0 03 c1 33 c2 03 75 d8 81 3d ?? ?? ?? ?? 21 01 00 00 89 45 fc 75 18 53 ff 15 ?? ?? ?? ?? 68 a0 2e 40 00 53 53 53 ff 15 ?? ?? ?? ?? 8b 45 fc 33 c6 29 45 f0 89 45 fc 8d 45 f4 e8 ?? ?? ?? ?? ff 4d e4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDM_2147890115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDM!MTB"
        threat_id = "2147890115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 8d 44 24 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_USS_2147891285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.USS!MTB"
        threat_id = "2147891285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 8d 4d fc e8 ?? ?? ?? ?? 8b 45 f8 8b 4d f4 8b 7d d8 8d 14 18 8b c3 d3 e8 8b 4d fc 03 cf 03 45 dc 33 c1 33 c2 29 45 f0 89 45 fc 8b 45 e0 29 45 f8 ff 4d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_UST_2147891341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.UST!MTB"
        threat_id = "2147891341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e0 04 03 44 24 30 8d 34 29 c1 e9 05 89 44 24 14 8b d9 83 fa 1b 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 14 03 5c 24 28 c7 05 ?? ?? ?? ?? 00 00 00 00 33 de 33 d8 2b fb 8b d7 c1 e2 04 89 54 24 14 8b 44 24 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_HAS_2147891641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.HAS!MTB"
        threat_id = "2147891641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 10 03 6c 24 20 c7 05 ?? ?? ?? ?? 00 00 00 00 33 eb 33 e8 2b f5 8b d6 c1 e2 04 89 54 24 10 8b 44 24 24 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d 1c 37 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d6 c1 ea 05 03 54 24 28 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 d3 31 54 24 10 c7 05 ?? ?? ?? ?? ff ff ff ff 8b 44 24 10 29 44 24 14 81 c7 47 86 c8 61 ff 4c 24 18 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_J_2147892152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.J!MTB"
        threat_id = "2147892152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 d3 e8 8d 34 17 03 45 ?? 33 c6 31 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_J_2147892152_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.J!MTB"
        threat_id = "2147892152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 44 24 30 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 c3 31 44 24 14 c7 05 ?? ?? ?? ?? ff ff ff ff 8b 44 24 14 29 44 24 18 81 c7 47 86 c8 61 4d 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_EC_2147892162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.EC!MTB"
        threat_id = "2147892162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {c1 e0 04 89 01 c3 81 00 e1 34 ef c6 c3}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CCCC_2147892318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CCCC!MTB"
        threat_id = "2147892318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 8b c8 c1 ea ?? 03 54 24 ?? c1 e1 ?? 03 4c ?? 24 03 c3 33 d1 33 d0 2b f2 8b ce}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 c1 e8 ?? 03 c5 33 c7 31 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_KAL_2147892622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.KAL!MTB"
        threat_id = "2147892622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 44 24 24 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 c3 31 44 24 10 c7 05 34 52 28 02 ff ff ff ff 8b 44 24 10 29 44 24 14 81 c7 47 86 c8 61 4d 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_DT_2147892789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.DT!MTB"
        threat_id = "2147892789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sapimohibozayocexojikeyefa kacujawemojimenadanedom" ascii //weight: 1
        $x_1_2 = "lewayivesurejumew" ascii //weight: 1
        $x_1_3 = "Hakerivipa dejurepo zotofucuwo" ascii //weight: 1
        $x_1_4 = "mifipesanahewoxezusuwopaxexoc" ascii //weight: 1
        $x_1_5 = "bevevenowewakobanudamuro" ascii //weight: 1
        $x_1_6 = "cexolenoruzodejesuxarenic popiri bin xujogihulozuwihivofizehunu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASM_2147892914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASM!MTB"
        threat_id = "2147892914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 33 c0 8d 54 24 1c 89 44 24 1c 89 44 24 20 89 44 24 24 89 44 24 28 89 44 24 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASM_2147892914_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASM!MTB"
        threat_id = "2147892914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 05 61 b8 42 00 69 c6 05 62 b8 42 00 72 c6 05 67 b8 42 00 50 c6 05 6d b8 42 00 74 c6 05 6e b8 42 00 00 c6 05 63 b8 42 00 74 c6 05 6c b8 42 00 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASM_2147892914_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASM!MTB"
        threat_id = "2147892914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 e8 a5 42 00 57 a3 20 e9 42 00 ff d6 50 e8 ?? ?? ?? ?? c7 04 24 d4 a5 42 00 57 a3 24 e9 42 00 ff d6 50 e8 ?? ?? ?? ?? c7 04 24 b8 a5 42 00 57 a3 28 e9 42 00 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_K_2147893131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.K!MTB"
        threat_id = "2147893131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 75 f8 8b 4d f4 8d 04 37 31 45 fc d3 ee 03 75 d0 81 3d ?? ?? ?? ?? 21 01 00 00 75 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BIR_2147893549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BIR!MTB"
        threat_id = "2147893549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 8b c8 c1 ea 05 03 54 24 34 c1 e1 04 03 4c 24 28 03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 10 8b 44 24 2c 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d 2c 3b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_JAH_2147893885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.JAH!MTB"
        threat_id = "2147893885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 ea 03 c6 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 e0 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ec 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f0 d3 ee 03 75 d4 81 3d ?? ?? ?? ?? 21 01 00 00 75 0a 53 ff 15 ?? ?? ?? ?? 8b 45 f8 31 75 fc 8b 4d fc 29 4d e8 81 45 f0 ?? ?? ?? ?? ff 4d e4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASF_2147894057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASF!MTB"
        threat_id = "2147894057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f5 31 74 24 10 8b 44 24 10 29 44 24 14 c7 44 24 18 00 00 00 00 8b 44 24 38 01 44 24 18 2b 5c 24 18 ff 4c 24 20 0f}  //weight: 1, accuracy: High
        $x_1_2 = {03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 10 8b 44 24 2c 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d 2c 3b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AMBB_2147894947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AMBB!MTB"
        threat_id = "2147894947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 8b cf c1 e1 04 03 4c 24 2c 8b c7 c1 e8 05 03 44 24 38 8d 14 3b 33 ca}  //weight: 1, accuracy: High
        $x_1_2 = {89 74 24 1c 8b 44 24 30 01 44 24 1c 8b 44 24 14 33 44 24 1c 89 44 24 1c 8b 4c 24 1c 89 4c 24 1c 8b 44 24 1c 29 44 24 18 8b 54 24 18 c1 e2 04 89 54 24 14 8b 44 24 34 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8b 44 24 18 8d 2c 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASG_2147895159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASG!MTB"
        threat_id = "2147895159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c5 8d 0c 37 33 c1 89 54 24 18 89 44 24 10 89 1d [0-4] 8b 44 24 18 01 05 [0-4] 8b 15 [0-4] 89 54 24 38 89 5c 24 18 8b 44 24 38 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 44 24 18 89 44 24 18 8b 44 24 18 29 44 24 14 8b 4c 24 14 c1 e1 04 89 4c 24 10 8b 44 24 2c 01 44 24 10 81 3d [0-4] be 01 00 00 8b 44 24 14 8d 1c 07 75}  //weight: 1, accuracy: Low
        $x_1_2 = {31 5c 24 10 8b 44 24 18 31 44 24 10 a1 [0-4] 2b 74 24 10 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDO_2147895249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDO!MTB"
        threat_id = "2147895249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c6 8b d6 c1 e0 04 c1 ea 05 03 54 24 ?? 03 c5 8d 0c 37 33 c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_NF_2147895401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.NF!MTB"
        threat_id = "2147895401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 ea 05 03 d5 8b c8 c1 e1 04 89 54 24 1c 03 cb 8d 14 06 33 ca 89 4c 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASBM_2147895474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASBM!MTB"
        threat_id = "2147895474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wijiwuferuwanarahup fefonopohoxocugihaporemofolul" ascii //weight: 1
        $x_1_2 = "saveriwiy dapetabecabeduhokas buy lexoganomakafaluwaxururimamud fobowirikeponanisewizu" ascii //weight: 1
        $x_1_3 = "rurotovuveyuhajexosufacuja" ascii //weight: 1
        $x_1_4 = "gevihiyerudugicewedigucibodapuw nor" ascii //weight: 1
        $x_1_5 = "losawalufeyudirisirapihiposibu" ascii //weight: 1
        $x_1_6 = "rowolomosafarogesunebunizusakin siciju" ascii //weight: 1
        $x_1_7 = "rovikovapizi kecozecicezugavoy kidovubotimoyiku sirikisayihutuz" ascii //weight: 1
        $x_1_8 = "ribimigeca carosujuwoposegegevidix lokuvicuyecuhigalumiyadepe xulahoyoma wegusehos" ascii //weight: 1
        $x_1_9 = "dabavisolayixofanedasecilihojo" ascii //weight: 1
        $x_1_10 = "wizasofupivusocusowupupavoxurug" ascii //weight: 1
        $x_1_11 = "wuyevusococekop zegofudegewikezivisahitatejuhej" ascii //weight: 1
        $x_1_12 = "zuwumoxucironevaxuy" ascii //weight: 1
        $x_1_13 = "bivavuvufukovunurocotexusu tisazolakanevuji jufonojijasiwaremawopegor" ascii //weight: 1
        $x_1_14 = "fuwexorovuvividenev soyavewisiyunawibehiyaj hanuvimahanolitoneyuy suwopijow" ascii //weight: 1
        $x_1_15 = "xicihucujihatiwomihazuy wusucehadebiwevizeroxoxelivu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_SmokeLoader_MYB_2147895823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MYB!MTB"
        threat_id = "2147895823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 89 4d e8 8b 4d f0 d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 c3 8b c8 8b 45 e8 31 45 fc 33 4d fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 4d e8 75}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 03 c7 33 c2 31 45 fc 8b 45 fc 29 45 f4 8d 45 ec e8 ?? ?? ?? ?? ff 4d e4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GAA_2147896213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GAA!MTB"
        threat_id = "2147896213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 e2 04 03 d3 03 c8 33 d1 89 54 24 10 89 35 ?? ?? ?? ?? 8b 44 24 24 01 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 54 24 3c 89 74 24 24 8b 44 24 3c 01 44 24 24 8b 44 24 10 33 44 24 24 89 44 24 24 8b 44 24 24}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c6 89 44 24 10 8b 44 24 24 31 44 24 10 8b 44 24 10 29 44 24 1c c7 44 24 20 00 00 00 00 8b 44 24 ?? 01 44 24 20 29 44 24 14 ff 4c 24 2c 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDA_2147896466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDA!MTB"
        threat_id = "2147896466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d3 e8 89 7d e8 89 35 ec da 42 00 03 45 c8 33 c7 31 45 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_L_2147896609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.L!MTB"
        threat_id = "2147896609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 d3 ea 03 c7 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 dc 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ec 75 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ZZQ_2147896702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ZZQ!MTB"
        threat_id = "2147896702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 54 24 2c 8b c8 c1 e1 04 89 54 24 18 03 cd 8d 14 06 33 ca 89 4c 24 10 89 3d ?? ?? ?? ?? 8b 44 24 18 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 34 89 7c 24 18 8b 44 24 34 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 4c 24 18}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c7 89 44 24 10 8b 44 24 18 31 44 24 10 8b 44 24 10 29 44 24 1c 81 c6 ?? ?? ?? ?? ff 4c 24 24 0f 85 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_M_2147896775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.M!MTB"
        threat_id = "2147896775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c7 89 44 24 10 8b 44 24 18 31 44 24 10 8b 44 24 10 29 44 24 1c 81 c6 ?? ?? ?? ?? ff 4c 24 24 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CHC_2147896889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CHC!MTB"
        threat_id = "2147896889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 45 f8 8b 4d f4 8b f0 d3 ee 8d 14 07 31 55 fc 03 75 d4 81 3d ?? ?? ?? ?? 21 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AMAZ_2147897130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AMAZ!MTB"
        threat_id = "2147897130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 ec c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 d8 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_HDA_2147897780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.HDA!MTB"
        threat_id = "2147897780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 45 fc 8b 45 d4 01 45 fc 8b 55 f4 8b 4d f8 8b c2 d3 e8 8d 3c 13 81 c3 ?? ?? ?? ?? 03 45 dc 33 c7 31 45 fc 8b 45 fc 29 45 f0 ff 4d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_O_2147898105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.O!MTB"
        threat_id = "2147898105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 55 fc 8b 45 d8 01 45 fc 8b 45 f4 8b 4d f8 8d 14 01 8b 4d f0 d3 e8 8b 4d fc 03 c3 33 c2 33 c8 89 4d fc 2b f1 8b 45 e0 29 45 f8 83 ef 01 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CHZ_2147898552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CHZ!MTB"
        threat_id = "2147898552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 89 4d fc 8b 45 e4 01 45 fc 8b 55 f4 8b 4d f8 8b f2 d3 ee 8d 04 17 31 45 fc 03 75 e0 81 3d ?? ?? ?? ?? 21 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c6 2b d8 81 c7 ?? ?? ?? ?? 83 6d ec 01 89 45 fc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_P_2147898644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.P!MTB"
        threat_id = "2147898644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 30 89 7c 24 18 8b 44 24 30 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 4c 24 18 89 4c 24 18 8b 44 24 18 29 44 24 14 8b 4c 24 14 8b c1 c1 e0 04 03 44 24 2c 81 3d ?? ?? ?? ?? be 01 00 00 89 44 24 10 8d 34 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AM_2147899160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AM!MTB"
        threat_id = "2147899160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 01 8b cb ff 46 ?? 8b 56 ?? 8b 46 ?? c1 e9 08 88 0c 02 ff 46 ?? 8b 4e ?? a1 ?? ?? ?? ?? 88 1c 08 ff 05 ?? ?? ?? ?? 81 fd ?? ?? ?? ?? 0f 8c ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 46 0c 03 86 ?? ?? ?? ?? 35 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 6a ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 83 f0 ?? 09 86 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 48 ?? 8b 86 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 03 c1 31 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_Q_2147899295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.Q!MTB"
        threat_id = "2147899295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4d f0 8b 4d f8 8b f3 d3 ee c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 dc 8b 45 f0 31 45 fc 81 3d ?? ?? ?? ?? e6 09 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASBN_2147899501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASBN!MTB"
        threat_id = "2147899501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Focabup-Liho podavagajewudu hixuyebac rucuzoy xabisil" wide //weight: 1
        $x_1_2 = "Jilolu nup cuyadovesepoxHCobebemoso murulasagum vimun lajixofojusiki ruya doricosodobutex gijeyay" wide //weight: 1
        $x_1_3 = "TGixakevayiyiheg rajovixibiwimu lajuwad pocujowum wukakohu zicutiy ruw zarinowalalawu" wide //weight: 1
        $x_1_4 = "hDuw rulufamomeke fedivaheti yibibayukege roxasohitis canoxoj milerejeda lojinapabajer yozu denomamexarak" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_GLM_2147899640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.GLM!MTB"
        threat_id = "2147899640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 ec 8b 45 ec 89 45 f0 8b 75 f8 8b 4d f4 8b 55 f0 31 55 fc d3 ee 03 75 d4 81 3d ?? ?? ?? ?? 21 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c6 81 c3 47 86 c8 61 2b f8 83 6d e4 ?? 89 45 fc 89 5d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDS_2147899661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDS!MTB"
        threat_id = "2147899661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 8d f8 f7 ff ff 30 04 39 83 fb 0f 75 1e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AAAK_2147899689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AAAK!MTB"
        threat_id = "2147899689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 10 30 04 0e 83 ff 0f 75 12 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 46 3b f7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_NL_2147899706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.NL!MTB"
        threat_id = "2147899706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 75 fc 89 75 f0 8b 45 f0 83 45 f4 ?? 29 45 f4 83 6d f4 ?? 8b 55 f4 c1 e2 ?? 89 55 fc 8b 45 e4 01 45 fc 8b 55 f4 8b 4d f8 8b f2 d3 ee 8d 04 17 31 45 fc 03 75 e0 81 3d ?? ?? ?? ?? ?? ?? 00 00 75 12}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_S_2147899730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.S!MTB"
        threat_id = "2147899730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bezematevaneri fedilovewe" ascii //weight: 1
        $x_1_2 = "fedabomalozosatebusuhuzogisarojotasikuyinegizowuvovezax" ascii //weight: 1
        $x_1_3 = "tacusuhicage" ascii //weight: 1
        $x_1_4 = "xupakesopopakuxo" ascii //weight: 1
        $x_1_5 = "hayeliyapavizovowinigaxomacowiwapihicivoje" ascii //weight: 1
        $x_1_6 = "Yuhegoveson daxelowam zitaj roborile" ascii //weight: 1
        $x_1_7 = "Rimavowegal buhaviluzu tesoyaz jicuk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASES_2147900234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASES!MTB"
        threat_id = "2147900234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tzurebizajivebiledik" wide //weight: 1
        $x_1_2 = "Tavuzirepefozak yun delobopaxu#Medi mugenux bawiluvopocep vinominu" wide //weight: 1
        $x_1_3 = "bkakakefagaxepijos" wide //weight: 1
        $x_1_4 = "Zasabixobezoz besovab" wide //weight: 1
        $x_1_5 = "yetonodivohafotipukoyavir dasacokosevisocu kocedecesikagoyufohibihicazihozo mitud huxeduraxivosuyewac" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_CYC_2147900507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.CYC!MTB"
        threat_id = "2147900507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 dc 8b 45 ec 31 45 fc 33 55 fc 89 55 d8 8b 45 d8 83 45 ?? 64}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c2 d3 e8 8b 4d fc 81 c7 47 ?? ?? ?? 89 7d e8 03 45 d0 33 45 ec 33 c8 2b f1 83 eb 01 89 4d fc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_T_2147900584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.T!MTB"
        threat_id = "2147900584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 f0 8b 45 f0 89 45 ec 8b 55 f8 8b 4d f4 8b c2 d3 e8 8b 4d fc 03 c3 33 45 ec 33 c8 8d 45 e8 89 4d fc 2b f1 e8 ?? ?? ?? ?? 83 ef 01 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASET_2147900756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASET!MTB"
        threat_id = "2147900756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jodovohozadozumajelipo" wide //weight: 1
        $x_1_2 = "yahoheveretelipasobisadada" wide //weight: 1
        $x_1_3 = "giduvamakevedoxagibikeyibix" wide //weight: 1
        $x_1_4 = "vamorogukajac" wide //weight: 1
        $x_5_5 = "lehelaroruwonozifovohiwerepono" ascii //weight: 5
        $x_1_6 = "larogaparavosopimotohizecenafifu" wide //weight: 1
        $x_1_7 = "fadadudohawafohukabemidehe" wide //weight: 1
        $x_1_8 = "tatikecijujerobokoviraz" wide //weight: 1
        $x_1_9 = "xinihekeludigag" wide //weight: 1
        $x_1_10 = "morebucoxozivib" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SmokeLoader_RDT_2147900914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDT!MTB"
        threat_id = "2147900914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 0c 30 04 31 83 7d 0c 0f 75 57}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDT_2147900914_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDT!MTB"
        threat_id = "2147900914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e8 fa fe ff ff 30 04 33 83 ff 0f 75 21}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_U_2147900940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.U!MTB"
        threat_id = "2147900940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 01 45 fc 8b 45 fc 31 45 08 8b 45 08 8b e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_HGG_2147901154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.HGG!MTB"
        threat_id = "2147901154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 f0 8b 45 f0 89 45 ec 8b 75 f8 8b 4d f4 d3 ee 03 75 dc 8b 45 ec 31 45 fc 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c6 81 c3 ?? ?? ?? ?? 2b f8 83 6d e0 01 89 45 fc 89 5d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_V_2147901413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.V!MTB"
        threat_id = "2147901413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 f0 8b 45 f0 89 45 ec 8b 55 f8 8b 4d f4 d3 ea 03 55 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 c2 81 c7 ?? ?? ?? ?? 2b f0 83 eb ?? 89 45 ?? 89 7d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_W_2147901553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.W!MTB"
        threat_id = "2147901553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 45 f0 8b 45 f0 89 45 ec 8b 55 f8 8b 4d f4 d3 ea 03 d3 8b 45 ec 31 45 fc 31 55 fc 2b 7d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PADH_2147902151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PADH!MTB"
        threat_id = "2147902151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d3 ea 89 45 ec 8b 45 fc c7 05 ac b3 af 02 ee 3d ea f4 03 55 d4 89 45 e8 89 75 f0 8b 45 ec 01 45 f0 8b 45 f0 31 45 e8 8b 45 e8 33 d0 89 45 fc 89 55 f0 8b 45 f0 83 45 f8 64 29 45 f8 83 6d f8 64 8b 45 f8 c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 45 f8 8d 0c 03 89 4d ec 8b 4d f4 d3 e8 03 45 d0 89 45 f0 8b 45 ec 31 45 fc 81 3d b4 b3 af 02 03 0b 00 00 75 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_SHK_2147902411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.SHK!MTB"
        threat_id = "2147902411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 ea 03 c6 89 45 ec 03 55 d4 8b 45 ec 31 45 fc 31 55 fc 2b 7d fc 8b 45 dc 29 45 f8 ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PADJ_2147902482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PADJ!MTB"
        threat_id = "2147902482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d6 03 c6 d3 ea 89 45 e4 8b 45 fc c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 d4 89 45 f0 89 7d e8 8b 45 e4 01 45 e8 8b 45 e8 31 45 f0 8b 45 f0 33 c2 2b d8 8b c3 c1 e0 04 89 45 fc 8b 45 cc 01 45 fc 8b 4d f4 8b 45 f8 8b f3 d3 ee 03 c3 89 45 e4 03 75 dc 8b 45 e4 31 45 fc 81 3d ?? ?? ?? ?? 03 0b 00 00 75 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PADM_2147902636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PADM!MTB"
        threat_id = "2147902636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ff 2d 75 06 6a 00 6a 00 ff d5 e8 ?? ?? ?? ?? 30 04 1e 83 ff 0f 75 08}  //weight: 1, accuracy: Low
        $x_1_2 = {51 c7 04 24 f0 43 03 00 83 04 24 0d a1 ?? ?? ?? ?? 0f af 04 24 05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 25 ff 7f 00 00 59 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d7 6a 00 ff d3 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 81 fe fc 6a 17 00 0f 8f 7d 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PADN_2147903011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PADN!MTB"
        threat_id = "2147903011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c2 2b f8 8b c7 c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 4d f8 8b 45 f4 8b f7 d3 ee 03 c7 89 45 e8 03 75 d4 8b 45 e8 31 45 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PADO_2147903012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PADO!MTB"
        threat_id = "2147903012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 c7 04 24 f0 43 03 00 83 04 24 0d a1 ?? ?? ?? ?? 0f af 04 24 05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 25 ff 7f 00 00 59 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 20 55 8b 2d ?? ?? ?? ?? 8b ff e8 8b ff ff ff 30 04 1e 83 ff 0f 75 04 6a 00 ff d5 46 3b f7 7c ea 5d 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_TOY_2147903768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.TOY!MTB"
        threat_id = "2147903768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c7 89 45 e4 8b 45 e8 c1 e8 05 89 45 ?? 8b 45 d4 01 45 ?? 8b 45 fc c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f0 89 5d ?? 8b 45 e4 01 45 e8 8b 45 e8 31 45 f0 8b 45 f0 31 45 f8 2b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASEU_2147905041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASEU!MTB"
        threat_id = "2147905041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d3 e8 03 45 ?? 89 45 f8 8b 45 ?? 31 45 fc 8b 45 fc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_X_2147905496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.X!MTB"
        threat_id = "2147905496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 45 d0 89 45 f0 33 45 e4 31 45 fc 8b 45 fc 29 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_X_2147905496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.X!MTB"
        threat_id = "2147905496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 ec 89 55 f8 8b 45 ?? 01 45 f8 8b 45 f8 31 45 ec 8b 4d f0 8b 45 ec 33 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_MAT_2147906668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.MAT!MTB"
        threat_id = "2147906668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 0c 30 83 ff 0f 75 1b 00 81 05 ?? ?? ?? ?? c3 9e 26 00 8a 0d 9a ?? ?? ?? 8b 44 24 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PADT_2147909799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PADT!MTB"
        threat_id = "2147909799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 0d ?? ?? ?? ?? 81 e1 ff 7f 00 00 89 0a c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 18 83 c0 64 89 44 24 10 83 6c 24 10 64 8a 4c 24 10 8b 44 24 14 30 0c 30 83 bc 24 5c 08 00 00 0f 75 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASL_2147910095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASL!MTB"
        threat_id = "2147910095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 f8 8b 4d fc 33 4d ?? 8b 45 f8 03 45 ?? 33 c1 89 4d fc}  //weight: 2, accuracy: Low
        $x_2_2 = {01 45 f8 8b 45 f8 33 45 ?? 31 45 fc 8b 45 fc 29 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDX_2147910296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDX!MTB"
        threat_id = "2147910296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 45 f0 8b 45 e8 c1 e8 05 89 45 f8 8b 4d fc 33 4d f0 8b 45 f8 03 45 d0 33 c1 89 4d fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RXE_2147911204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RXE!MTB"
        threat_id = "2147911204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 85 f8 ?? ?? ?? 83 c0 64 89 85 f4 ?? ?? ?? 83 ad f4 ?? ?? ?? 64 8a 8d f4 ?? ?? ?? 30 0c 33 83 ff 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PADZ_2147911396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PADZ!MTB"
        threat_id = "2147911396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f8 89 45 f4 8d 45 f4 50 e8 b8 ff ff ff 83 c4 04 8b 45 f4 83 c0 64 89 45 f8 83 6d f8 64 8a 4d f8 30 0c 1e 83 ff 0f 75 22}  //weight: 1, accuracy: High
        $x_1_2 = {69 c0 fd 43 03 00 81 3d ?? ?? ?? ?? 9e 13 00 00 a3 f8 21 34 02 75 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASGE_2147911909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASGE!MTB"
        threat_id = "2147911909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 c0 64 89 45 ?? 83 6d ?? 64 8b 45 bc 8a 4d ?? 03 c6 30 08 83 fb 0f 75}  //weight: 4, accuracy: Low
        $x_1_2 = "lopeyevecavinoxigilaketet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDAA_2147912425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDAA!MTB"
        threat_id = "2147912425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 44 24 10 2b e8 89 44 24 14 8b c5 c1 e0 04 89 44 24 10 8b 44 24 2c 01 44 24 10 8b c5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PAEH_2147912586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PAEH!MTB"
        threat_id = "2147912586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 44 24 10 2b d8 89 44 24 14 8b c3 c1 e0 04 89 44 24 10 8b 44 24 28 01 44 24 10 8b c3 c1 e8 05 89 44 24 14 8b 44 24 2c 01 44 24 14 8d 04 2b 33 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 18 8d ad ?? ?? ?? ?? 4e 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PAEJ_2147912686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PAEJ!MTB"
        threat_id = "2147912686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 44 24 18 8b c7 c1 e0 04 89 44 24 10 8b 44 24 28 01 44 24 10 8b 4c 24 14 8b c7 c1 e8 05 03 cf 89 44 24 18 8b 44 24 2c 01 44 24 18 8b 44 24 18 33 c1 31 44 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 30 29 44 24 14 4b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_PAEO_2147913055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.PAEO!MTB"
        threat_id = "2147913055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 44 24 14 8b c3 c1 e0 04 89 44 24 10 8b 44 24 2c 01 44 24 10 8b c3 c1 e8 05 89 44 24 14 8b 44 24 30 01 44 24 14 8d 04 1e 33 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 1c 8d 4c 24 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_KOF_2147914400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.KOF!MTB"
        threat_id = "2147914400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 89 7d f8 e8 ?? ?? ?? ?? 8a 45 f8 30 04 33 83 7d 08 0f 59 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_WRD_2147914718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.WRD!MTB"
        threat_id = "2147914718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c7 2b f0 8b c6 c1 e8 05 03 ce 89 45 ?? 8b 85 ?? fd ff ff 01 45 ?? 8b c6 c1 e0 04 03 85 ?? fd ff ff 33 45 ?? 33 c1 2b d8 89 9d ?? fd ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_TZZ_2147914870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.TZZ!MTB"
        threat_id = "2147914870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 a5 f8 f7 ff ff 00 8d 8d f8 f7 ff ff e8 ?? ?? ?? ?? 8a 85 f8 f7 ff ff 30 04 37 83 fb 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_STE_2147915011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.STE!MTB"
        threat_id = "2147915011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 33 f6 85 db 7e ?? 83 a5 f8 fb ff ff 00 8d 8d f8 fb ff ff e8 ?? ?? ?? ?? 8a 85 f8 fb ff ff 30 04 37 83 fb 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASGH_2147915035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASGH!MTB"
        threat_id = "2147915035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {81 ff fe d0 00 00 7d 07 56 ff 15 ?? ?? ?? 00 56 ff 15 ?? ?? ?? 00 56 ff 15 ?? ?? ?? 00 56 56 ff 15 ?? ?? ?? 00 81 ff ee 37 3a 00 7f 09 47 81 ff 2f e5 00 00 7c}  //weight: 3, accuracy: Low
        $x_1_2 = {81 ff ee 37 3a 00 7f 09 47 81 ff 2f e5 00 00 7c}  //weight: 1, accuracy: High
        $x_1_3 = {81 ff 85 ed 8c 05 7f 09 47 81 ff b1 02 65 1f 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AXA_2147915320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AXA!MTB"
        threat_id = "2147915320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 8b 4d 70 33 c7 2b f0 8b c6 c1 e8 05 89 b5 ?? ?? ?? ?? 03 ce 89 45 6c 8b 85 ?? ?? ?? ?? 01 45 6c c1 e6 04 03 b5 68 fe ff ff 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_SMZ_2147915609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.SMZ!MTB"
        threat_id = "2147915609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 70 8b 45 70 8b 8d 88 fe ff ff 03 c7 03 cb 33 c1 33 c6 29 85 80 fe ff ff 8b 85 80 fe ff ff c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BBX_2147915719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BBX!MTB"
        threat_id = "2147915719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 34 84 82 02 ee 3d ea f4 89 45 70 8b 85 70 fe ff ff 01 45 70 8b b5 78 fe ff ff 8b 8d 80 fe ff ff 03 8d 78 fe ff ff c1 e6 04 03 b5 ?? ?? ?? ?? 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BBZ_2147915838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BBZ!MTB"
        threat_id = "2147915838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 70 8b 45 70 8b 95 80 fe ff ff 03 c7 03 d3 33 c2 33 c1 29 85 78 fe ff ff 8b 85 ?? ?? ?? ?? c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_IIA_2147915930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.IIA!MTB"
        threat_id = "2147915930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 70 8b 45 70 03 85 10 ff ff ff 8b 95 ?? ?? ?? ?? 03 d7 33 c2 33 c1 2b d8 8b c3 c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70 8b 85 0c ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ROD_2147916071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ROD!MTB"
        threat_id = "2147916071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 70 8b 45 70 03 85 0c ff ff ff 8d 14 3b 33 c2 33 c1 29 85 18 ff ff ff 8b 85 18 ff ff ff c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_TOE_2147916199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.TOE!MTB"
        threat_id = "2147916199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 3b df 7e 29 8d 4d fc 89 7d fc e8 ?? ?? ?? ?? 8b 45 08 8a 4d fc 03 c6 30 08 83 fb 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_YYT_2147916577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.YYT!MTB"
        threat_id = "2147916577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8a 4d fc 03 c2 30 08 42 3b d6 7c e5 83 fe 2d 75 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_YQT_2147916645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.YQT!MTB"
        threat_id = "2147916645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8a 4d fc 03 c6 30 08 83 7d 0c 0f 75 0d 57 ff 75 0c ff d3 57 ff 15 ?? ?? ?? ?? 46 3b 75 0c 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AR_2147916761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AR!MTB"
        threat_id = "2147916761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 8b 45 e8 01 45 fc 8b 4d f8 8b c7 c1 e0 ?? 03 45 ?? 03 cf 33 c1 81 3d ?? ?? ?? ?? 03 0b 00 00 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_KWW_2147917147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.KWW!MTB"
        threat_id = "2147917147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 e8 c9 ff ff ff 8b 45 08 59 8a 4d fc 03 c6 30 08 83 fb 0f 75 ?? 6a 00 ff 75 fc ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_ASGI_2147918380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.ASGI!MTB"
        threat_id = "2147918380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 c3 30 08 83 7d 0c 0f 75}  //weight: 5, accuracy: High
        $x_5_2 = {8b 4d fc 5f 5e 33 cd 5b e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RDAC_2147921739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RDAC!MTB"
        threat_id = "2147921739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 95 dc f3 ff ff 8b 85 d8 f3 ff ff 8b 75 0c 30 14 38 83 fe 0f 75 5b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_SKF_2147926685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.SKF!MTB"
        threat_id = "2147926685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d f0 03 4d f8 8b 45 f0 c1 e8 05 89 45 f4 8b 45 f4 03 45 d8 33 d9 33 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_EABZ_2147929475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.EABZ!MTB"
        threat_id = "2147929475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c0 46 89 44 24 0c 83 6c 24 0c 0a 90 83 6c 24 0c 3c 8a 44 24 0c 30 04 3b 83 fd 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_EANN_2147929551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.EANN!MTB"
        threat_id = "2147929551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 a4 24 ec 00 00 00 8b 84 24 ec 00 00 00 81 ac 24 ac 01 00 00 ?? ?? ?? ?? 8a 84 0e 3b 2d 0b 00 88 04 39 41}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BB_2147929616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BB!MTB"
        threat_id = "2147929616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 85 dc fd ff ff 0f b6 b4 05 f8 fe ff ff 8b 45 08 8b 8d e4 fd ff ff 0f b6 14 08 31 f2 88 14 08 8b 85 e4 fd ff ff 83 c0 01 89 85 e4 fd ff ff e9}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_EAC_2147929663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.EAC!MTB"
        threat_id = "2147929663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 55 ec 8d 04 1f 33 d0 33 55 fc 89 55 dc 8b 45 dc 29 45 f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BC_2147930132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BC!MTB"
        threat_id = "2147930132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {01 45 fc 8b 45 f8 8b cb c1 e1 04 03 4d dc 8d 14 18 33 ca 33 4d fc}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BD_2147930134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BD!MTB"
        threat_id = "2147930134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 6c 24 04 0a ?? 83 6c 24 04 3c 8a 44 24 04 30 04 37 83 fb 0f 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_SZXB_2147930971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.SZXB!MTB"
        threat_id = "2147930971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {83 c0 46 89 44 24 14 83 6c 24 14 0a 83 6c 24 14 3c 8a 44 24 14 30 04 1f 47 3b fd 7c}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_AMDA_2147930972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.AMDA!MTB"
        threat_id = "2147930972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 f0 01 0f af 86 ?? 00 00 00 8b d3 c1 ea 10 89 86 ?? 00 00 00 8b 86 ?? 00 00 00 83 f0 01 29 46 ?? 8b 86 ?? 00 00 00 88 14 01 8b d3 ff 46}  //weight: 3, accuracy: Low
        $x_1_2 = {83 c4 14 33 ff 8b 46 ?? 33 86 ?? 00 00 00 33 46 ?? 89 86 ?? 00 00 00 a1 ?? ?? ?? ?? 6a 24 8b 40}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 40 2b 86 ?? 00 00 00 01 46 ?? a1 ?? ?? ?? ?? 03 46 ?? 83 f0 25 01 46 ?? a1 ?? ?? ?? ?? 8b 40 ?? 0f af 46 ?? 89 46 ?? a1 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 8b 0c 38 a1 ?? ?? ?? ?? 33 8e ?? 00 00 00 89 0c 07 83 c7 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BE_2147931030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BE!MTB"
        threat_id = "2147931030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 44 24 14 83 6c 24 14 0a 83 6c 24 14 3c 8a 44 24 14 30 04 1f 47 3b fd 7c}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_EAQP_2147932052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.EAQP!MTB"
        threat_id = "2147932052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 08 8b 0d ?? ?? ?? ?? 8a 8c 01 d6 38 00 00 8b 15 ?? ?? ?? ?? 88 0c 02 c9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_BF_2147935993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.BF!MTB"
        threat_id = "2147935993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {01 f3 83 ec 04 89 14 24 ba 00 00 00 00 01 da 31 02 5a 5b 53}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_EAHT_2147936239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.EAHT!MTB"
        threat_id = "2147936239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c1 e8 05 03 44 24 28 03 cd 33 c1 8d 0c 3b 33 c1 2b f0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_RGB_2147941796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.RGB!MTB"
        threat_id = "2147941796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6a 00 ff 75 f8 6a 00 6a 00 6a 00 6a 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmokeLoader_EA_2147951918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmokeLoader.EA!MTB"
        threat_id = "2147951918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {2f 00 63 00 20 00 63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00 20 00 90 00 02 00 10 00 2e 00 70 00 64 00 66 00 20 00 90 00 02 00 10 00 2e 00 62 00 61 00 74 00 20 00 26 00 20 00 90 00 02 00 10 00 2e 00 62 00 61 00 74 00 90 00 00 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

