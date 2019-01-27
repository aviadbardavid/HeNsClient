var reqId
var timeoutPeriod = 35 * 1000;

function onQuerySubmitFromWebpage(queryType) {
    $("#resultList").empty();
    reqId = "0"
    console.log("Value submitted:" + $("#queryInput").val());
    $.ajax 
    ({
        url     : "/data",
        type    : 'POST',
        dataType: 'json',
        data    : JSON.stringify({ name: 'query', data: $("#queryInput").val(), type: queryType, requestId: reqId }),

        success : function (data, textStatus, xhr) { onReceiveAnswerFromServer(data, textStatus, xhr) },
        error   : function (xhr,  textStatus     ) {
            if (textStatus === 'timeout'){
                modalError('Request time out!');
            }else{
                modalError('Error ' + xhr.status +': ' + xhr.statusText +" - " + xhr.responseJSON.text);
            }
        },
        timeout : timeoutPeriod
    });
}

function onReceiveAnswerFromServer(message, textStatus, xhr) {
    if (!($("#progressModal").data('bs.modal') || {})._isShown) {
        $("#progressModal").modal('show');
    }
    if(xhr.status != 200)
    {
        modalError('Error ' + xhr.status +': ' + xhr.statusText +" - " + message.text);
        return;
    }
    reqId = message.requestId;
    switch (message.progress) {
        case -1:
            $("#btnCloseModal").show();
            modalError('Error ' + xhr.status +': ' + xhr.statusText +" - " + message.text);
            break;
        case 100:
            $('#modalMessage').text('Finished!');

            setProgressBarToSuccess();

            if (!($("#progressModal").data('bs.modal') || {})._isShown) {
                $("#progressModal").modal('show');
            }
            var resultList = message.resultsList;
            populateResults(resultList);
            let counter = 3;
            $("#btnCloseModal").text("Close (" + counter + ")");
            $("#btnCloseModal").show();
            setInterval(function () {
                counter--;
                if (counter >= 0) {
                    $("#btnCloseModal").text("Close (" + counter + ")");
                }
                if (counter === 0) {
                    $("#progressModal").modal('hide');
                }
            }, 1000);
            break;
        default:
            $("#btnCloseModal").hide();
            $('#modalMessage').text(message.text);
            $('#progressBar').css('width', message.progress + '%')
            .attr('aria-valuenow', message.progress)
            .removeClass('bg-danger')
            .removeClass('bg-success')
            .addClass('bg-primary')
            .addClass('progress-bar-animated')
            .addClass('progress-bar-striped');
            $.ajax
            ({
                url     : "/data",
                type    : 'POST',
                dataType: 'json',
                data    : JSON.stringify({ name: 'statusUpdate', data: message.progress, requestId: reqId}),
                
                success : function (data, textStatus, xhr) { onReceiveAnswerFromServer(data, textStatus, xhr) },
                error   : function (xhr,  textStatus     ) {
                    if (textStatus === 'timeout'){
                        modalError('Request time out!');
                    }else{
                        modalError('Error ' + xhr.status +': ' + xhr.statusText +" - " + xhr.responseJSON.text);
                    }
                },
                timeout : timeoutPeriod
            });
            break;

    }
}

function modalError(errorText) {
    reqId = "0";
    $('#modalMessage').text(errorText);
    
    setProgressBarToError();
    
    $("#btnCloseModal").text("Close");
    if (!($("#progressModal").data('bs.modal') || {})._isShown) {
        $("#progressModal").modal('show');
    }
    $("#btnCloseModal").show();
}

function setProgressBarToError() {
    $('#progressBar').css('width', '100%')
    .attr('aria-valuenow', '100')
    .addClass('bg-danger')
    .removeClass('progress-bar-animated')
    .removeClass('progress-bar-striped');
}

function setProgressBarToSuccess() {
    $('#progressBar').css('width', '100%')
    .attr('aria-valuenow', '100')
    .addClass('bg-success')
    .removeClass('progress-bar-animated')
    .removeClass('progress-bar-striped');
}

function populateResults(resultList) {
    console.log("Reulst list populating!");
    $("#resultList").empty();
    for (var i = 0; i < resultList.length; i++) {
        var aElement = document.createElement("a");
        aElement.className = "list-group-item list-group-item-action";
        aElement.target = "_blank";
        aElement.href = resultList[i].url;
        aElement.innerText = resultList[i].text;
        $("#resultList").append(aElement);
    }
}
