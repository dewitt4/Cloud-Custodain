

Reports


Every policy execution by cloud maid generates a json report that is stored to an s3 bucket


S3 bucket structure

 /cloud-maid-acct-name
    /policies/
      /offhours-stop
      /offhours-start
      /tag-compliance-mark
      /tag-compliance-terminate


# Crontab Schedule


Run the off hours start at 7:15, 8:15, 9:15, 10:15 Additional runs for timezone specification on offhours

15 7,8,9,10 * * 1,2,3,4,5 /usr/local/maid/maid/bin/cron-runner offhours-start tag-compliance-mark tag-compliance-unmark
15 19,20,21,22 * * 1,2,3,4,5 /usr/local/maid/maid/bin/cron-runner offhours-stop tag-compliance-mark tag-compliance-terminate tag-compliance-unmark
