# Collect post code snippets and post descriptions from all history of each post.
SELECT PostBlockVersion.PostHistoryId, PostBlockTypeId,PostBlockVersion.PostId post_id, LocalID, post_q.Id question_id, Content, Length, post_a.Score vote, post_q.Tags tags, post_history.CreationDate date
  FROM `sotorrent-org.2020_12_31.PostBlockVersion` PostBlockVersion
      # inner join question posts
      INNER JOIN `sotorrent-org.2020_12_31.Posts` post_a
      ON PostBlockVersion.PostId = post_a.Id
      # inner join answer post 
      INNER JOIN `sotorrent-org.2020_12_31.Posts` post_q
      ON post_a.ParentId = post_q.Id
      #innder join history create date
      INNER JOIN `sotorrent-org.2020_12_31.PostHistory` post_history
      ON PostBlockVersion.PostHistoryId = post_history.Id
  WHERE
    post_q.PostTypeId=1
    AND post_a.PostTypeId=2
    AND post_a.Score >=0
    AND (LOWER(post_q.Tags) LIKE '%<c>%' OR LOWER(post_q.Tags) LIKE '%<c++>%'OR LOWER(post_q.Tags) LIKE '%<android>%' )
    AND REGEXP_CONTAINS(post_a.Body,  r'(.*)(?i)(<code>|</code>)(.*)')
   
  GROUP BY PostBlockVersion.PostHistoryId, PostBlockVersion.PostId, Content, post_q.Id, post_a.Score, Length, PostBlockTypeId, LocalID, post_q.Tags, post_history.CreationDate
  ORDER BY post_a.Score DESC, PostBlockVersion.PostId DESC, PostBlockVersion.PostHistoryId DESC