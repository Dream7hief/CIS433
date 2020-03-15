import sys
import mailbox

msgs = []

def gen_summary(filename):
    mbox = mailbox.mbox(filename)
    for message in mbox:
       subj = message['subject']
       msgs.append(subj)
       # print(subj)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: python genarchivesum.py mbox')
        sys.exit(1)

    gen_summary(sys.argv[1])
    for msg in msgs:
        print(msg)
