# coding:utf-8

import os
import platform
import locale
import ctypes
import win32runas


def win32_notify( msg='msg', title='Title'):
    res = ctypes.windll.user32.MessageBoxW(None, msg, title, 1)
    # Yes:1 No:2
    return res == 1

def reset_teredo():
    gp_split = b'[\x00'
    gp_teredo = '\x00'.join(list('v6Transition\x00;Teredo')).encode()

    with open(gp_regpol_file, 'rb') as f:
        gp_regpol_old = f.read().split(gp_split)

    gp_regpol_new = [gp for gp in gp_regpol_old if gp_teredo not in gp]

    if len(gp_regpol_new) != len(gp_regpol_old) and \
            win32_notify(notice_text, notice_title):
        with open(gp_regpol_file, 'wb') as f:
            f.write(gp_split.join(gp_regpol_new))
        os.system(sysnative + '\\gpupdate /target:computer /force')

def main():
    if os.name != 'nt':
        return

    sysver = platform.version()
    if sysver < '6':
        # Teredo item was added to Group Policy starting with Windows Vista
        return

    windir = os.environ.get('windir')
    if not windir:
        return

    try:
        zh_locale = locale.getdefaultlocale()[0] == 'zh_CN'
    except:
        zh_locale = None

    if zh_locale:
        notice_title = u'\u63d0\u9192'
        notice_text = u'\u53d1\u73b0\u7ec4\u7b56\u7565 Teredo \u8bbe\u7f6e\uff0c\u662f\u5426\u91cd\u7f6e\uff1f'
    else:
        notice_title = 'Notice'
        notice_text = 'Found Teredo settings in Group Policy, do you want to reset it?'

    sys64 = os.path.exists(windir + '\\SysWOW64')
    pe32 = platform.architecture()[0] == '32bit'
    sysalias = 'Sysnative' if sys64 and pe32 else 'System32'
    sysnative = '%s\\%s' % (windir, sysalias)
    gp_regpol_file = sysnative + '\\GroupPolicy\\Machine\\Registry.pol'

    if os.path.exists(gp_regpol_file):
        if not win32runas.is_admin():
            win32runas.runas(os.path.abspath(__file__))
            return
        reset_teredo()

if '__main__' == __name__:
    main()
