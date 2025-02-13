rule Trojan_Win32_Clustinex_A_2147682377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clustinex.gen!A"
        threat_id = "2147682377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clustinex"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\documents and settings\\johndoe\\local settings\\application data\\opera\\opera\\widgets\\" wide //weight: 1
        $x_1_2 = "c:\\extension.oex" wide //weight: 1
        $x_1_3 = "c:\\temp\\\\extension.oex" wide //weight: 1
        $x_1_4 = "c:\\temp\\\\ff_extension.xpi" wide //weight: 1
        $x_1_5 = "\"id\",\"minversion\",\"maxversion\")values(\"%addon_id%\",\"{ec8030f7-c20a-464f-9b0e-13a3a9e97384}\", \"3.*\", \"20.*\")" wide //weight: 1
        $x_1_6 = "\"1354210658765\",\"0\",\"1\",\"0\",\"457433\",\"http://smilemore.ru/extensions/smileonline41.xpi\",\"\",\"0\",\"0\",\"0\",\"0\")" wide //weight: 1
        $x_1_7 = "wuid-cbeaf715-2808-d940-b4c8-289c17591126" wide //weight: 1
        $x_1_8 = "yandexbrowser_widgetwin_1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clustinex_B_2147683374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clustinex.gen!B"
        threat_id = "2147683374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clustinex"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\" alt=\"0%\" style=\"width:" ascii //weight: 1
        $x_1_2 = "c:/documents and settings/all users/application data/temp/htm/" ascii //weight: 1
        $x_1_3 = "c:\\documents and settings\\all users\\application data\\temp\\htm\\js\\bramus\\jsprogressbarhandler.js" ascii //weight: 1
        $x_1_4 = "c:\\documents and settings\\all users\\application data\\temp\\htm\\js\\prototype\\prototype.js" ascii //weight: 1
        $x_1_5 = "{34a715a0-6587-11d0-924a-0020afc7ac4d}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clustinex_C_2147683391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clustinex.gen!C"
        threat_id = "2147683391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clustinex"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ")c:\\temp\\g828af" wide //weight: 1
        $x_1_2 = "9d2f54a8-7d42-4065-ae11-d56966ff2fcb" ascii //weight: 1
        $x_1_3 = ";c:\\temp\\g828af" wide //weight: 1
        $x_1_4 = "\\!\\#\\%\\'\\)\\+\\-\\/\\1\\3\\5\\7\\9\\;\\=\\?\\a\\c\\e\\g\\i\\k\\m\\o\\*" ascii //weight: 1
        $x_1_5 = "program files\\common files\\system\\ole db\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clustinex_D_2147683471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clustinex.gen!D"
        threat_id = "2147683471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clustinex"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".event.triggered=h,e[h]())}catch(p){}n&&(e[l]=n),f.event.triggered=b}}return c.result}},handle:function(c){c=f.event.fix(c||a.event);var d=((f._data(this,\"events\")||{})[c.type]||[]).slice(0),e=!c.exclusive&&!" ascii //weight: 1
        $x_1_2 = "c:\\documents and settings\\all users\\application data\\temp\\htm\\js\\bramus\\jsprogressbarhandler.js" ascii //weight: 1
        $x_1_3 = "c:\\documents and settings\\all users\\application data\\temp\\htm\\js\\prototype\\prototype.js" ascii //weight: 1
        $x_1_4 = "e?f.cache[a[f.expando]]:a[f.expando];return!!a&&!l(a)},data:function(a,c,d,e){if(!!f.acceptdata(a)){var g=f.expando,h=typeof c==\"string\",i,j=a.nodetype,k=j?f.cache:a,l=j?a[f.expando]:a[f.expando]&&f.expando" ascii //weight: 1
        $x_1_5 = "{34a715a0-6587-11d0-924a-0020afc7ac4d}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

