  # Collect post comments including security-related keywords.
  SELECT post_a.Id post_id, post_q.Title Title, post_q.Id question_id, comments.Text comment, post_a.Score vote
  FROM `sotorrent-org.2020_12_31.Posts` post_a
      INNER JOIN `sotorrent-org.2020_12_31.Posts` post_q
      ON  post_q.Id = post_a.ParentId
      INNER JOIN `sotorrent-org.2020_12_31.Comments` comments
      ON comments.PostId = post_a.Id
  WHERE
    post_q.PostTypeId=1
    AND post_a.PostTypeId = 2
    AND post_a.Score >=0
    AND REGEXP_CONTAINS(post_a.Body,  r'(.*)(?i)(<code>|</code>)(.*)')
    AND (LOWER(post_q.Tags) LIKE '%<c>%' OR LOWER(post_q.Tags) LIKE '%<c++>%'OR LOWER(post_q.Tags) LIKE '%<android>%')
    AND (
     REGEXP_CONTAINS(comments.Text,  r'(.*)(?i)(incorrect|vulnerab|harm|undefine|unpredict|unsafe|secur|malicious|dangerous|critical|bad|unprivileged|negative|stable|invalid|vulnerab| fault|defect|sanit|mistake|flaw| bug| hack|infinite|loop|secur|overflow|error|mistake|remote|exploit|mitigat|realloc|heap|privilege|underflow|patch|injection|segment|DoS|denial-of-service|initiali|xss|leak|authentication|authori|attack|out-of-bounds|use-after-free|trigger|dereference|corruption|crash|memory|NULL|flaw|hack| fix|change|modify|exploit|mitigat|realloc|invoke|inject|ensure|reject|initiali|leak|authori|update|attack|trigger|lock|corrupt|fail|crash|prevent|avoid|access)(.*)')
     ) 
  GROUP BY post_a.Id,  post_q.Title, post_q.Id, post_a.Body, comments.Text, post_a.Score
  ORDER BY post_a.Score DESC, post_a.Id DESC