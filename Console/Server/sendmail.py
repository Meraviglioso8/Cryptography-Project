import smtplib


gmail_user = 'sender'
gmail_app_password = 'gmail app pasword'

sent_from = gmail_user
sent_to = ['receiver']
sent_subject = "Hey Friends!"
sent_body = ("Hello\n\n"
             "I have to inform that you are now in SUSPECTED table by our application!\n"
             "\n"
             "Seeya,\n"
             "Group6\n")

email_text = """\
From: %s
To: %s
Subject: %s

%s
""" % (sent_from, ", ".join(sent_to), sent_subject, sent_body)

#try until success
try:
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.ehlo()
    server.login(gmail_user, gmail_app_password)
    server.sendmail(sent_from, sent_to, email_text)
    server.close()

    print('Email sent!')
except Exception as exception:
    print("Error: %s!\n\n" % exception)